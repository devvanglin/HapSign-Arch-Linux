"""系统默认浏览器登录模块。

使用系统默认浏览器打开华为 OAuth 登录页，用户在浏览器中手动登录，
通过本地 HTTP 服务拦截回调拿到 tempToken。

流程（逆向自 DevEco Studio HiAiLoginService）：
  1. 找空闲端口，生成 CSRF code (UUID 去横线)
  2. 启动本地 HTTP 服务等待 POST /callback
  3. 系统默认浏览器打开登录页 ?port={port}&appid=1007&code={uuid}
  4. 用户在浏览器中手动输入账号密码并登录
  5. 华为 OAuth 服务端通过浏览器回调本地 HTTP 服务，携带 tempToken, siteId, code
  6. 校验 code（CSRF），返回 tempToken
"""

import logging
import socket
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from hapsign.config import APP_ID, BASE_URL, LOGIN_AUTH_PATH

logger = logging.getLogger(__name__)

# 回调超时（秒）—— 给用户足够时间处理验证码/二次验证
_CALLBACK_TIMEOUT = 600
_CALLBACK_HOST = "127.0.0.1"
_MAX_CALLBACK_BODY_SIZE = 64 * 1024

# 登录成功重定向路径
_LOGIN_SUCCESS_PATH = "console/DevEcoIDE/loginSuccess"


def _find_free_port() -> int:
    """找本机空闲 TCP 端口。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((_CALLBACK_HOST, 0))
        return s.getsockname()[1]


def _make_callback_handler(
    expected_code: str, callback_data: dict, callback_event: threading.Event
):
    """创建回调 HTTP 请求处理器类（闭包注入共享状态）。

    华为 OAuth 服务端在用户登录成功后，通过浏览器向本地回调服务器
    POST 表单数据：tempToken, siteId, code。
    """

    class _CallbackHandler(BaseHTTPRequestHandler):
        def _process_params(self, params: dict) -> None:
            """处理回调参数，校验 CSRF code 并保存 tempToken。"""
            # 回调中含有 tempToken。日志只记录字段名，避免用户分享日志时泄漏凭据。
            logger.debug("[callback] fields received: %s", sorted(params))

            received_code = params.get("code", "")
            if received_code != expected_code:
                logger.warning("[callback] CSRF code mismatch")
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"invalid csrf code")
                return

            callback_data["tempToken"] = params.get("tempToken", "")
            callback_data["siteId"] = params.get("siteId", "")
            callback_data["code"] = params.get("code", "")
            callback_event.set()

            redirect_url = f"{BASE_URL}/{_LOGIN_SUCCESS_PATH}"
            self.send_response(302)
            self.send_header("Location", redirect_url)
            self.end_headers()

        def do_POST(self):
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > _MAX_CALLBACK_BODY_SIZE:
                self.send_response(413)
                self.end_headers()
                return
            body = self.rfile.read(content_length).decode("utf-8")
            logger.debug("[callback] POST path=%s", self.path)
            params = parse_qs(body)
            params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            self._process_params(params)

        def do_GET(self):
            parsed = urlparse(self.path)
            logger.debug("[callback] GET path=%s", parsed.path)
            if parsed.path != "/callback":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
                return
            params = parse_qs(parsed.query)
            params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            self._process_params(params)

        def log_message(self, fmt, *args):
            logger.debug("[http] %s - %s", self.client_address[0], fmt % args)

    return _CallbackHandler


class BrowserLogin:
    """使用系统默认浏览器登录。

    使用示例::

        login = BrowserLogin()
        temp_token = login.login("CN")
    """

    def login(self, country: str = "CN") -> str:
        """打开华为登录页，用户手动登录，拦截回调拿 tempToken。

        Args:
            country: 国家码，默认 ``"CN"``，仅用于后续 token 交换

        Returns:
            tempToken 字符串

        Raises:
            RuntimeError: 任意步骤失败时抛出
        """
        # ── 1. 找空闲端口 ──
        port = _find_free_port()

        # ── 2. 生成 CSRF code（UUID 去横线，与原始插件一致） ──
        csrf_code = uuid.uuid4().hex

        # ── 3. 构建登录 URL ──
        login_url = (
            f"{BASE_URL}/{LOGIN_AUTH_PATH}?port={port}&appid={APP_ID}&code={csrf_code}"
        )

        logger.info("[LOGIN] callback port=%d", port)

        # ── 4. 启动本地 HTTP 回调服务 ──
        callback_data: dict = {}
        callback_event = threading.Event()

        handler_class = _make_callback_handler(csrf_code, callback_data, callback_event)
        server = ThreadingHTTPServer((_CALLBACK_HOST, port), handler_class)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        logger.info("[LOGIN] callback server listening on %s:%d", _CALLBACK_HOST, port)

        try:
            # ── 5. 打开系统默认浏览器，等待回调 ──
            self._browser_login_and_wait(login_url, callback_event)
        finally:
            # ── 6. 关闭 HTTP 服务 ──
            server.shutdown()
            server.server_close()

        # ── 7. 校验并返回 tempToken ──
        temp_token = callback_data.get("tempToken", "")
        if not temp_token:
            raise RuntimeError(
                "Callback did not contain tempToken. Login may have been cancelled."
            )

        return temp_token

    def _browser_login_and_wait(
        self,
        login_url: str,
        callback_event: threading.Event,
    ) -> None:
        """用系统默认浏览器打开登录页并等待回调。

        用户在浏览器中手动完成登录（输入账号密码、处理验证码/二次验证）。

        Args:
            login_url: 完整登录 URL
            callback_event: 收到回调后 set，本方法等待其被 set 后退出

        Raises:
            RuntimeError: 系统浏览器启动失败或回调超时
        """
        try:
            opened = webbrowser.open(login_url, new=1, autoraise=True)
        except Exception as e:
            raise RuntimeError(f"无法打开系统浏览器: {e}") from e

        if not opened:
            raise RuntimeError(
                "系统没有可用的默认浏览器。请先设置 xdg 默认浏览器后重试。"
            )

        print("[LOGIN] 已在系统默认浏览器打开华为官方登录页")
        print("[LOGIN] 请自行完成账号、验证码或二次验证")
        print(f"[LOGIN] 正在等待登录回调（最多 {_CALLBACK_TIMEOUT} 秒）...")

        if not callback_event.wait(timeout=_CALLBACK_TIMEOUT):
            raise RuntimeError(
                f"登录超时：{_CALLBACK_TIMEOUT} 秒内没有收到回调，请重新运行。"
            )
