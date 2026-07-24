# HapSign Arch Linux

在 Arch Linux 上通过华为开发者账号为 HarmonyOS HAP 自动生成调试签名，并通过 HDC 安装到真机。

> [!IMPORTANT]
> 本仓库基于原项目 [guantw/HapSign](https://github.com/guantw/HapSign) 修改。
> 原项目作者为 [guantw](https://github.com/guantw)，本仓库保留原作者信息和 MIT
> License。本项目主要增加 Arch Linux、HarmonyOS Command Line Tools 和系统浏览器登录支持，
> 不代表原作者参与或认可本仓库后续的全部修改。

> [!WARNING]
> 本项目是非官方开发工具，与华为没有隶属、合作或背书关系。在线接口可能随时变化，
> 请仅将其用于自己账号、设备和应用的合法开发调试，并自行确认相关服务条款。

## 与原项目的关系

- 原项目：[guantw/HapSign](https://github.com/guantw/HapSign)
- 原作者：[guantw](https://github.com/guantw)
- Arch Linux 适配仓库：[devvanglin/HapSign-Arch-Linux](https://github.com/devvanglin/HapSign-Arch-Linux)
- 许可证：[MIT License](LICENSE)

本仓库是在原项目代码基础上进行的 Linux 适配，不是从零重新实现，也不改变原项目代码的著作权归属。

## 主要修改

- 支持 Arch Linux 原生运行，不需要 Windows 虚拟机。
- 支持官方 HarmonyOS Command Line Tools，不强制安装 DevEco Studio。
- 使用系统默认浏览器打开华为官方登录页面，不再启动 Playwright 独立浏览器。
- 账号、密码、验证码和二次验证全部由用户在浏览器中自行完成。
- 使用 `127.0.0.1` 本地回调接收临时登录结果。
- 自动创建调试证书、登记设备、创建调试 Profile、签名 HAP 并通过 HDC 安装。
- 使用独立的 `arch_debug_<teamId>.cer`，不会删除或覆盖 DevEco Studio 创建的
  `auto_debug_<teamId>.cer`。
- 所有项目共用同一套 Arch 调试证书和私钥，每个 Bundle 单独保存自己的 Profile。
- 使用强随机 keystore 密码，并以 `0600` 权限保存在本机状态目录。
- 登录 Token 仅在当前流程中临时使用，流程结束后自动删除。
- HDC 使用覆盖安装模式 `install -r`。

## 工作流程

```text
系统默认浏览器打开华为官方登录页
  → 用户自行完成登录、验证码或二次验证
  → 本地回调获取临时 Token
  → 调用签名服务申请或复用 Arch 调试证书
  → 登记当前 HarmonyOS 设备
  → 为当前 Bundle 创建调试 Profile
  → 使用官方 hap-sign-tool.jar 签名 HAP
  → 使用 hdc install -r 安装到设备
  → 删除本地临时 Token 缓存
```

## 环境要求

- Arch Linux 或兼容发行版。
- Python 3.11 或更高版本。
- Java 17 和 `keytool`。
- HarmonyOS Command Line Tools。
- HarmonyOS 真机，已开启开发者模式和 USB 调试并完成 HDC 授权。
- 已完成必要认证的华为开发者账号。

在 Arch Linux 上可以安装基础运行环境：

```bash
sudo pacman -S python jdk17-openjdk
```

本项目默认查找以下 SDK 目录：

```text
~/.local/share/harmonyos/command-line-tools/sdk/default/openharmony
```

该目录下需要存在：

```text
toolchains/hdc
toolchains/lib/hap-sign-tool.jar
```

## 安装

```bash
git clone https://github.com/devvanglin/HapSign-Arch-Linux.git
cd HapSign-Arch-Linux

python -m venv .venv
source .venv/bin/activate
python -m pip install .
```

安装完成后会提供 `hapsign` 命令：

```bash
hapsign --version
```

也可以不安装命令，直接从源码运行：

```bash
python main.py --hap /path/to/app-unsigned.hap
```

## 配置路径

如果 SDK 不在默认位置，可以设置环境变量：

```bash
export HARMONY_SDK_ROOT=/path/to/sdk/default/openharmony
```

其他可选变量：

```bash
# Java 可执行文件
export HAPSIGN_JAVA=/usr/bin/java

# keytool 可执行文件
export HAPSIGN_KEYTOOL=/usr/bin/keytool

# 本地状态与签名材料目录
export HAPSIGN_STATE_DIR="$HOME/.local/state/harmonyos/hapsign"

# 可选：自行指定 keystore 密码；不设置时自动生成强随机密码
export HAPSIGN_KEYSTORE_PASSWORD='your-strong-password'
```

## 使用方法

先构建未签名的 HAP。Hvigor 默认输出通常位于：

```text
entry/build/default/outputs/default/entry-default-unsigned.hap
```

确认设备连接：

```bash
hdc list targets -v
```

然后执行：

```bash
hapsign --hap entry/build/default/outputs/default/entry-default-unsigned.hap
```

工具会从 HAP 内的 `module.json` 自动读取 `bundleName`，通常不需要手动指定。

首次为一个新 Bundle 签名时，系统默认浏览器会打开华为官方登录页。登录成功后，工具会自动完成
Profile 创建、HAP 签名和真机安装。同一个 Bundle 后续构建可以复用已有签名材料。

### 手动指定 Bundle

```bash
hapsign \
  --hap entry/build/default/outputs/default/entry-default-unsigned.hap \
  --bundle-name com.example.myapplication
```

### 更换调试设备

Profile 包含设备 UDID。如果换了一台真机，需要刷新签名 Profile：

```bash
hapsign \
  --hap entry/build/default/outputs/default/entry-default-unsigned.hap \
  --refresh-signing
```

### system_basic 能力

默认创建 Test Profile，APL 为 `normal`。如果应用已经在 AGC 注册并确实需要
`system_basic` 能力，可以使用：

```bash
hapsign --hap app-unsigned.hap --enable-capability
```

如果应用不满足 Real Profile 条件，工具会回退到普通 Test Profile。

## 命令行参数

```text
hapsign --hap <HAP路径> [选项]

--hap               未签名 HAP 路径，必填
--bundle-name       手动指定 Bundle 名称
--country           账号国家码，默认 CN
--device-type       设备类型码，默认 4
--work-dir          当前 Bundle 的签名输出目录
--enable-capability 尝试创建 system_basic Real Profile
--refresh-token     强制重新登录并刷新当前签名流程
--refresh-signing   重新为当前设备和 Bundle 创建 Profile
-v, --verbose       输出详细日志
--version           显示版本
```

设备类型码：

| 类型码 | 设备 |
| --- | --- |
| `4` | 手机、平板 |
| `2` | 穿戴设备 |
| `8` | 智慧屏 |
| `9` | 路由器 |
| `1` | 轻量级穿戴设备 |

## 本地文件

默认状态目录：

```text
~/.local/state/harmonyos/hapsign/
├── credentials/
│   ├── .keystore_password
│   ├── arch_debug.p12
│   ├── arch_debug.csr
│   └── arch_debug.cer
└── signing_files/
    └── com.example.myapplication/
        ├── arch_debug_com.example.myapplication.p7b
        ├── metadata.json
        └── entry-default-unsigned_signed.hap
```

`credentials/` 是所有项目共用的 Arch 调试身份；`signing_files/<bundleName>/` 保存每个应用自己的
Profile 和签名结果。

这些文件不在 Git 仓库中，但仍然属于敏感开发材料。不要上传、分享或放入公开同步目录。

## 证书保护

原项目会为了重新申请证书而删除同名远端证书。本仓库修改了这一行为：

- 不删除账号中已有的调试证书。
- 不使用 DevEco Studio 的 `auto_debug_<teamId>.cer` 名称。
- 单独使用 `arch_debug_<teamId>.cer`。
- 如果账号证书数量达到上限，流程会失败并停止，不会自动删除任何证书。

这样可以避免影响同一账号在 Windows DevEco Studio 中已有的自动签名配置。

## 登录与安全

- 登录页面来自华为官方域名，并由系统默认浏览器打开。
- 本程序不读取浏览器输入的账号、密码或验证码。
- 本地回调只监听 `127.0.0.1`。
- 回调使用随机 CSRF code 校验。
- 日志不会输出 `tempToken`。
- Token 缓存权限为 `0600`，并在流程结束时删除。
- keystore 密码和私钥不会写入项目源码目录。

更多信息见 [SECURITY.md](SECURITY.md)。

## 已知限制

- 登录验证码和二次验证必须由用户手动完成。
- 在线签名接口不是公开稳定 API，华为更新服务后工具可能需要同步适配。
- 当前默认 HAP `compatibleVersion` 为 API 20。
- 同时连接多台 HDC 设备时，建议只保留目标设备在线，避免安装目标不明确。
- 本工具只面向开发调试签名，不用于应用正式发布签名。

## 开发与测试

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

python -m ruff format --check hapsign tests
python -m ruff check hapsign tests
python -m pytest
```

本地单元测试不需要真实华为账号、网络或 HarmonyOS 设备。

## 致谢

- 感谢 [guantw](https://github.com/guantw) 创建原项目
  [HapSign](https://github.com/guantw/HapSign)。本仓库的认证、签名 API 和整体流程均建立在原项目工作基础上。
- 保留原项目中的 [BitFun](https://github.com/GCWing/BitFun) 致谢信息。
- 感谢 OpenHarmony、HarmonyOS 开发工具及相关社区项目。

## License

本项目沿用原项目的 [MIT License](LICENSE)。原始版权信息保留在许可证文件中：

```text
Copyright (c) 2026 guantw
```
