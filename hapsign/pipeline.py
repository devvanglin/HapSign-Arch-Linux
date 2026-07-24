"""登录、token 交换、签名材料申请、HAP 签名和安装的全流程编排。

缓存策略：
  1. Token 只在本次流程中临时缓存，流程结束时自动删除。
  2. 签名文件缓存：``signing_files/{bundle_name}/metadata.json`` 存储申请的
     签名文件路径，只要文件完整存在就复用。

缓存失效场景：
  - token 过期：缓存 token 用不了时自动刷新；刷新也失败则回退到重新登录。
  - 签名文件缺失：重新申请（用缓存 token，不重新登录）。
"""

import json
import logging
import os
import secrets
import zipfile
from datetime import date

from hapsign.api.capability_api import CapabilityAPI
from hapsign.api.cert_api import CertAPI
from hapsign.api.client import HuaweiSignClient, TokenExpiredError
from hapsign.api.device_api import DeviceAPI
from hapsign.api.provision_api import ProvisionAPI
from hapsign.config import (
    ACL_PERMISSION_WHITELIST,
    DEVICE_TYPE_PHONE,
    KEY_ALIAS,
    KEYSTORE_PASSWORD,
)
from hapsign.login.browser_login import BrowserLogin
from hapsign.models import AppBriefInfo, CertResult, ProvisionResult, TokenInfo
from hapsign.signing.hap_signer import HapSigner
from hapsign.signing.installer import Installer
from hapsign.signing.keytool_util import KeytoolUtil
from hapsign.token.token_exchange import TokenExchange

logger = logging.getLogger(__name__)

# 签名状态只保存在当前用户的私有状态目录。
STATE_DIR = os.environ.get(
    "HAPSIGN_STATE_DIR",
    os.path.expanduser("~/.local/state/harmonyos/hapsign"),
)
SIGNING_FILES_DIR = os.path.join(STATE_DIR, "signing_files")
CREDENTIALS_DIR = os.path.join(STATE_DIR, "credentials")


class SignPipeline:
    """签名 + 安装全流程编排。

    使用示例::

        pipeline = SignPipeline(
            hap_path="app.hap",
            bundle_name="com.example.myapp",
        )
        pipeline.run()
    """

    def __init__(
        self,
        hap_path: str,
        bundle_name: str,
        country: str = "CN",
        device_type: str = DEVICE_TYPE_PHONE,
        work_dir: str = "",
        enable_capability: bool = False,
        force_refresh_token: bool = False,
        force_refresh_signing: bool = False,
    ):
        self.hap_path = hap_path
        self.bundle_name = bundle_name
        self.country = country
        self.device_type = device_type
        self.enable_capability = enable_capability
        self.force_refresh_token = force_refresh_token
        self.force_refresh_signing = force_refresh_signing
        if work_dir:
            self.work_dir = work_dir
        else:
            self.work_dir = os.path.join(SIGNING_FILES_DIR, bundle_name)
        os.makedirs(SIGNING_FILES_DIR, exist_ok=True)
        os.makedirs(CREDENTIALS_DIR, exist_ok=True)
        os.makedirs(self.work_dir, exist_ok=True)
        for private_dir in (
            STATE_DIR,
            SIGNING_FILES_DIR,
            CREDENTIALS_DIR,
            self.work_dir,
        ):
            try:
                os.chmod(private_dir, 0o700)
            except OSError:
                pass
        self._password_path = os.path.join(CREDENTIALS_DIR, ".keystore_password")
        self.keystore_password = self._load_or_create_keystore_password()
        self._metadata_path = os.path.join(self.work_dir, "metadata.json")
        self._token_cache_path = os.path.join(SIGNING_FILES_DIR, ".token_cache.json")

        self._token_exchange = TokenExchange()
        self._token_info: TokenInfo | None = None
        self._client: HuaweiSignClient | None = None
        self._cert_api: CertAPI | None = None
        self._device_api: DeviceAPI | None = None
        self._provision_api: ProvisionAPI | None = None
        self._capability_api: CapabilityAPI | None = None
        self._token_from_cache = False

    def _load_or_create_keystore_password(self) -> str:
        """读取或生成仅供本地调试 keystore 使用的强随机密码。"""
        if KEYSTORE_PASSWORD:
            return KEYSTORE_PASSWORD
        if os.path.exists(self._password_path):
            with open(self._password_path, encoding="utf-8") as password_file:
                password = password_file.read().strip()
            if password:
                return password

        password = secrets.token_urlsafe(32)
        fd = os.open(self._password_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as password_file:
            password_file.write(password)
        return password

    # ── Token 缓存 ──────────────────────────────────────────────

    def _load_token_cache(self) -> dict | None:
        """加载当天的 token 缓存。

        条件：缓存存在、creation_date 是今天。
        """
        if not os.path.exists(self._token_cache_path):
            return None
        try:
            with open(self._token_cache_path, encoding="utf-8") as f:
                cache = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

        if cache.get("creation_date") != date.today().isoformat():
            logger.info("[cache] token 缓存非今日，跳过")
            return None
        if not cache.get("access_token") or not cache.get("user_id"):
            return None
        return cache

    def _save_token_cache(self) -> None:
        """保存当前 token 信息到缓存文件。"""
        if self._token_info is None:
            return
        cache = {
            "creation_date": date.today().isoformat(),
            "access_token": self._token_info.access_token,
            "refresh_token": self._token_info.refresh_token,
            "user_id": self._token_info.user_id,
            "user_name": self._token_info.user_name,
            "national_code": self._token_info.national_code,
            "real_name": self._token_info.real_name,
            "jwt_token": self._token_info.jwt_token,
        }
        os.makedirs(SIGNING_FILES_DIR, exist_ok=True)
        with open(self._token_cache_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
        try:
            os.chmod(self._token_cache_path, 0o600)
        except OSError as exc:
            logger.debug("无法限制 token 缓存文件权限: %s", exc)
        logger.info("[cache] token 缓存已保存: %s", self._token_cache_path)

    def _init_client_from_cache(self, cache: dict) -> None:
        """从缓存数据初始化 API 客户端。"""
        self._token_info = TokenInfo(
            access_token=cache["access_token"],
            refresh_token=cache.get("refresh_token", ""),
            user_id=cache["user_id"],
            user_name=cache.get("user_name", ""),
            national_code=cache.get("national_code", ""),
            real_name=cache.get("real_name", False),
            jwt_token=cache.get("jwt_token", ""),
        )
        self._client = HuaweiSignClient(
            access_token=self._token_info.access_token,
            uid=self._token_info.user_id,
        )
        self._cert_api = CertAPI(self._client)
        self._device_api = DeviceAPI(self._client)
        self._provision_api = ProvisionAPI(self._client)
        self._capability_api = CapabilityAPI(self._client)
        self._token_from_cache = True
        logger.info("[cache] 使用缓存 token")

    def _clear_token_cache(self) -> None:
        """清除 token 缓存文件。"""
        if os.path.exists(self._token_cache_path):
            os.remove(self._token_cache_path)
            logger.info("[cache] token 缓存已清除")

    # ── 签名文件缓存 ─────────────────────────────────────────────

    def _load_cached_metadata(self) -> dict | None:
        """加载仍完整存在的签名文件缓存。"""
        if not os.path.exists(self._metadata_path):
            return None
        try:
            with open(self._metadata_path, encoding="utf-8") as f:
                meta = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

        for key in ("p12_path", "cer_path", "p7b_path"):
            path = meta.get(key, "")
            if not path or not os.path.exists(path):
                logger.info("[cache] 签名文件缺失 (%s)", key)
                return None
        return meta

    def _save_metadata(
        self,
        p12_path: str,
        cer_path: str,
        p7b_path: str,
        team_id: str,
        cert_object_id: str,
        udid: str,
    ) -> None:
        """保存签名材料元数据。"""
        meta = {
            "creation_date": date.today().isoformat(),
            "bundle_name": self.bundle_name,
            "p12_path": p12_path,
            "cer_path": cer_path,
            "p7b_path": p7b_path,
            "team_id": team_id,
            "cert_object_id": cert_object_id,
            "udid": udid,
            "key_alias": KEY_ALIAS,
        }
        with open(self._metadata_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        try:
            os.chmod(self._metadata_path, 0o600)
        except OSError:
            pass
        logger.info("[cache] 签名文件元数据已保存: %s", self._metadata_path)

    # ── 主流程 ──────────────────────────────────────────────────

    def run(self) -> bool:
        """运行完整流程，并在退出前删除本地账号 token 缓存。"""
        try:
            return self._run()
        finally:
            self._clear_token_cache()

    def _run(self) -> bool:
        """执行签名安装流程，优先使用缓存。

        强制刷新逻辑：
        - force_refresh_token: 清除 token 缓存，强制重新登录
        - force_refresh_signing: 清除签名文件缓存，强制重新申请
        - 刷新 token 时自动连带刷新签名文件（否则只刷新 token 无意义）

        Returns:
            全部步骤成功返回 True，任一步骤失败返回 False。
        """
        # 强制刷新 token 时连带刷新签名文件
        if self.force_refresh_token:
            self._clear_token_cache()
            logger.info("[cache] 强制刷新 token 缓存")
            # token 刷新后签名文件也必须重新申请
            self.force_refresh_signing = True

        if not self.force_refresh_signing:
            signing_cached = self._load_cached_metadata()
        else:
            signing_cached = None
            logger.info("[cache] 强制刷新签名文件缓存")

        if signing_cached:
            logger.info("[cache] 签名文件已缓存，跳过登录和申请步骤")
            self._p12_path = signing_cached["p12_path"]
            self._cer_path = signing_cached["cer_path"]
            self._p7b_path = signing_cached["p7b_path"]
            steps = [
                ("签名 hap", self._step_sign_hap),
                ("安装 hap 到设备", self._step_install),
            ]
        else:
            # 需要申请签名文件，先确保有 token
            if not self.force_refresh_token:
                token_cached = self._load_token_cache()
            else:
                token_cached = None
            if token_cached:
                logger.info("[cache] 当天 token 已缓存，跳过登录")
                self._init_client_from_cache(token_cached)
            else:
                # 没有缓存 token，需要登录
                try:
                    self._step_login()
                    self._step_exchange_token()
                except Exception as e:
                    logger.error("x 登录失败: %s", e)
                    return False

            steps = [
                ("生成密钥对和 CSR", self._step_generate_keypair),
                ("申请证书", self._step_add_certificate),
                ("注册调试设备", self._step_register_device),
                ("创建调试 Profile", self._step_create_provision),
                ("签名 hap", self._step_sign_hap),
                ("安装 hap 到设备", self._step_install),
            ]
            if self.enable_capability:
                steps.insert(0, ("查询应用信息", self._step_get_app_info))

        for name, step in steps:
            logger.info("> %s ...", name)
            try:
                step()
            except TokenExpiredError as e:
                # 只有 token 真正失效才回退到重新登录
                logger.warning(
                    "x %s failed: token 已失效 (%s)，回退到重新登录",
                    name,
                    e,
                )
                self._token_from_cache = False
                self._clear_token_cache()
                try:
                    self._step_login()
                    self._step_exchange_token()
                    step()
                except Exception as retry_err:
                    logger.error("x %s failed after retry: %s", name, retry_err)
                    return False
            except Exception as e:
                logger.error("x %s failed: %s", name, e)
                return False
            logger.info("+ %s done", name)
        return True

    # ── 步骤实现 ────────────────────────────────────────────────

    def _step_login(self) -> None:
        """系统默认浏览器登录，用户手动输入账号密码，获取 tempToken。"""
        login = BrowserLogin()
        self._temp_token = login.login(self.country)

    def _step_exchange_token(self) -> None:
        """tempToken -> jwtToken -> accessToken，初始化 API 客户端，保存 token 缓存。"""
        jwt_token = self._token_exchange.exchange_temp_token(
            self._temp_token, self.country
        )
        token_info = self._token_exchange.get_access_token(jwt_token)
        self._token_info = token_info
        logger.info("登录成功")

        self._client = HuaweiSignClient(
            access_token=token_info.access_token,
            uid=token_info.user_id,
        )
        self._cert_api = CertAPI(self._client)
        self._device_api = DeviceAPI(self._client)
        self._provision_api = ProvisionAPI(self._client)
        self._capability_api = CapabilityAPI(self._client)

        # 保存 token 缓存，供同一天内复用
        self._save_token_cache()

    def _step_get_app_info(self) -> None:
        """查询应用简要信息，获取 appId 和 projectId。

        Real Provision 路径需要 appId 放入 provision/add 请求体。
        逆向自 AutoSigningHandleService.autoSignWhenEnableCapability。

        如果应用未在 AGC 注册（appInfos 为空），会回退到 Test Provision。
        """
        assert self._capability_api is not None
        team_id = self._with_refresh(self._cert_api.get_team_id)
        self._team_id = team_id
        logger.info("Team ID: %s", team_id)

        self._app_info: AppBriefInfo | None = self._with_refresh(
            self._capability_api.get_app_brief_info, team_id, self.bundle_name
        )
        if self._app_info is None:
            logger.warning(
                "应用 %s 未在 AGC 注册，回退到 Test Profile（APL=normal）",
                self.bundle_name,
            )
            self.enable_capability = False
            return

        if self._app_info.pure_flag != 1:
            logger.warning(
                "应用 pureFlag=%s 非 HarmonyOS 应用，回退到 Test Profile",
                self._app_info.pure_flag,
            )
            self.enable_capability = False
            return

        logger.info(
            "App ID: %s, Project ID: %s",
            self._app_info.app_id,
            self._app_info.project_id,
        )

    def _step_generate_keypair(self) -> None:
        """keytool 生成 EC 密钥对和 CSR。"""
        self._p12_path = os.path.join(CREDENTIALS_DIR, "arch_debug.p12")
        self._csr_path = os.path.join(CREDENTIALS_DIR, "arch_debug.csr")

        keytool = KeytoolUtil()
        self._new_keypair = not os.path.exists(self._p12_path)
        if self._new_keypair:
            keytool.generate_keypair(self._p12_path, KEY_ALIAS, self.keystore_password)
            try:
                os.chmod(self._p12_path, 0o600)
            except OSError:
                pass
        else:
            logger.info("复用本机已有 Arch 调试密钥")

        if not os.path.exists(self._csr_path) or self._new_keypair:
            self._csr_content = keytool.generate_csr(
                self._p12_path, KEY_ALIAS, self.keystore_password, self._csr_path
            )
        else:
            with open(self._csr_path, encoding="utf-8") as csr_file:
                self._csr_content = csr_file.read()

    def _step_add_certificate(self) -> None:
        """上传 CSR 申请证书，查询 certObjectId，下载 .cer 文件。

        流程（安全适配自 AutoSigningHandleService.generateCertificate）：
        1. 查询专用于 Arch 的证书；绝不删除账号中的任何证书
        2. 不存在时 POST cert/add → 只检查 code=0
        3. GET cert/list → 按证书名匹配获取 certObjectId
        4. POST reapply.url with sourceUrls=certObjectId → 获取下载 URL
        5. 下载 .cer 文件
        """
        assert self._cert_api is not None
        if not hasattr(self, "_team_id") or self._team_id is None:
            self._team_id = self._with_refresh(self._cert_api.get_team_id)
        team_id = self._team_id
        logger.info("Team ID: %s", team_id)

        try:
            self._with_refresh(self._cert_api.sign_agreement)
        except Exception:
            logger.debug("Agreement signing skipped (may already be signed)")

        cert_name = f"arch_debug_{team_id}.cer"

        existing_cert = None
        try:
            existing_cert = self._with_refresh(
                self._cert_api.find_cert, team_id, cert_name
            )
        except ValueError:
            pass

        if existing_cert is not None and getattr(self, "_new_keypair", False):
            raise RuntimeError(
                f"账号中已存在 {cert_name}，但本机没有与它配对的旧密钥。"
                "为保护现有证书，工具不会删除或覆盖它。"
            )

        if existing_cert is None:
            # 上传 CSR（Real Provision 路径需要 reqSource="IDE"）
            req_source = "IDE" if self.enable_capability else None
            self._with_refresh(
                self._cert_api.add_certificate,
                self._csr_content,
                team_id,
                cert_name,
                req_source,
            )
        else:
            logger.info("复用账号中已有的 Arch 调试证书（不会删除）")

        # 查询 certObjectId 和 cert id
        cert_info = self._with_refresh(self._cert_api.find_cert, team_id, cert_name)
        cert_object_id = str(cert_info.get("certObjectId", ""))
        cert_id = str(cert_info.get("id", ""))
        self._cert_result = CertResult(cert_object_id=cert_object_id, cert_id=cert_id)
        logger.info("Cert ID: %s, ObjectId: %s", cert_id, cert_object_id)

        self._cer_path = os.path.join(CREDENTIALS_DIR, "arch_debug.cer")
        self._with_refresh(
            self._cert_api.download_file,
            cert_object_id,
            team_id,
            self._cer_path,
        )

    def _step_register_device(self) -> None:
        """获取设备 UDID 并注册到华为平台，然后查询设备 ID。"""
        assert self._device_api is not None
        installer = Installer()
        self._udid = installer.get_udid()
        logger.info("已读取设备 UDID")

        self._with_refresh(
            self._device_api.add_device,
            self._udid,
            self.device_type,
            self._team_id,
        )

        # 查询设备列表获取设备 ID（provision API 需要的是 id 不是 udid）
        self._device_id = self._with_refresh(
            self._device_api.find_device_id, self._team_id, self._udid
        )
        logger.info("设备 ID: %s", self._device_id)

    def _step_create_provision(self) -> None:
        """创建调试 Profile，下载 .p7b 文件，删除远端 Profile，保存缓存元数据。

        provision API 的 certList 和 deviceList 需要的是 id（短数字），
        不是 certObjectId / udid（长字符串）。

        根据 enable_capability 选择：
        - Test Profile（APL=normal）：add.test.provision
        - Real Profile（APL=system_basic）：add.real.provision，额外需要 appId

        权限列表从 hap 的 module.json 提取 requestPermissions，
        通过 aclPermissionList 传递（compileSdk >= 9 时使用 ACL 预授权）。

        下载 .p7b 后删除远端 Profile（与 Java generateTestProfileFile 一致），
        因为 Profile 创建后会留下远端记录，需要清理。
        """
        assert self._provision_api is not None and self._cert_api is not None
        acl_perms = self._extract_permissions()
        if acl_perms:
            logger.info("ACL 权限列表: %s", acl_perms)

        if self.enable_capability and self._app_info is not None:
            logger.info("使用 Real Profile（APL=system_basic）")
            result: ProvisionResult = self._with_refresh(
                self._provision_api.add_real_provision,
                self._team_id,
                self.bundle_name,
                [self._cert_result.cert_id],
                [self._device_id],
                self._app_info.app_id,
                acl_permissions=acl_perms,
            )
        else:
            result = self._with_refresh(
                self._provision_api.add_test_provision,
                self._team_id,
                self.bundle_name,
                [self._cert_result.cert_id],
                [self._device_id],
                acl_permissions=acl_perms,
            )

        self._p7b_path = os.path.join(
            self.work_dir, f"arch_debug_{self.bundle_name}.p7b"
        )
        self._with_refresh(
            self._cert_api.download_file,
            result.provision_file_url,
            self._team_id,
            self._p7b_path,
        )

        # 删除远端 Profile（与 Java generateTestProfileFile 中的 deleteProvision 一致）
        if result.provision_id:
            try:
                self._with_refresh(
                    self._provision_api.delete_provision,
                    self._team_id,
                    result.provision_id,
                )
                logger.info("已删除远端 Profile (id=%s)", result.provision_id)
            except Exception as e:
                logger.debug("删除远端 Profile 失败（不影响流程）: %s", e)

        self._save_metadata(
            p12_path=self._p12_path,
            cer_path=self._cer_path,
            p7b_path=self._p7b_path,
            team_id=self._team_id,
            cert_object_id=self._cert_result.cert_object_id,
            udid=self._udid,
        )

    def _step_sign_hap(self) -> None:
        """用 hap-sign-tool 对 hap 包签名。"""
        hap_basename = os.path.splitext(os.path.basename(self.hap_path))[0]
        self._signed_hap_path = os.path.join(
            self.work_dir, f"{hap_basename}_signed.hap"
        )

        signer = HapSigner()
        signer.sign_hap(
            self.hap_path,
            self._cer_path,
            self._p7b_path,
            self._p12_path,
            KEY_ALIAS,
            self.keystore_password,
            self._signed_hap_path,
        )
        logger.info("签名后 hap: %s", self._signed_hap_path)

    def _step_install(self) -> None:
        """hdc install 安装签名后的 hap 到设备。"""
        installer = Installer()
        installer.install(self._signed_hap_path)

    # ── 工具方法 ────────────────────────────────────────────────

    def _extract_permissions(self) -> list[str]:
        """从 hap 的 module.json 提取 requestPermissions，按 ACL 白名单过滤。

        DevEco 的 PermissionUtil.getReqPermissions 会按 SDK 版本对应的白名单
        过滤权限，只把白名单内的权限放入 aclPermissionList。
        白名单外的权限（如 INTERNET、READ_CALENDAR）是普通权限，
        不需要 ACL 预授权，由系统安装时自动授予。
        """
        try:
            with zipfile.ZipFile(self.hap_path) as z:
                for name in z.namelist():
                    if name.lower() == "module.json":
                        data = json.loads(z.read(name))
                        perms = data.get("module", {}).get("requestPermissions", [])
                        all_names = [p["name"] for p in perms if "name" in p]
                        filtered = [
                            n for n in all_names if n in ACL_PERMISSION_WHITELIST
                        ]
                        skipped = [
                            n for n in all_names if n not in ACL_PERMISSION_WHITELIST
                        ]
                        if skipped:
                            logger.info(
                                "非 ACL 权限（普通权限，由系统授予）: %s", skipped
                            )
                        return filtered
        except Exception as e:
            logger.debug("提取权限列表失败: %s", e)
        return []

    def _with_refresh(self, func, *args, **kwargs):
        """执行 API 调用，token 失效时自动刷新并重试一次。"""
        try:
            return func(*args, **kwargs)
        except TokenExpiredError:
            logger.warning("Token 失效，尝试刷新...")
            new_token = self._token_exchange.refresh_access_token(
                self._token_info.jwt_token
            )
            self._client.access_token = new_token
            self._token_info.access_token = new_token
            self._save_token_cache()
            return func(*args, **kwargs)
