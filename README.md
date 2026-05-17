# SSHWarden

SSHWarden 是一个轻量的独立 SSH Agent，目标是把 Bitwarden 中保存的 SSH Key 暴露给本机 `ssh` / `git` 使用，同时避免运行完整 Bitwarden Desktop 客户端。

> 当前项目处于跨平台 baseline 设计和实现推进阶段。现有代码最完整的是 Windows 路径；Linux/macOS 是一等支持目标，但部分控制通道、自启动、存储路径和平台原生解锁能力仍在建设中。

## 项目目标

SSHWarden 的目标不是复刻完整 Bitwarden Desktop，而是提供一个专注于 SSH Agent 的轻量工具：

- 从 Bitwarden / Vaultwarden 同步 SSH Key
- 作为本地 SSH Agent 服务 `ssh`、`git`、Git commit signing 等客户端
- 在签名请求时显示授权对话框
- 支持锁定、解锁、自动锁定和本地加密缓存
- 支持 Windows、Linux 桌面会话、macOS 三个平台的完整用户体验

## 当前状态

| 能力 | 当前状态 |
|---|---|
| Bitwarden 登录与 SSH Key 同步 | 已实现 |
| SSH Agent 协议服务 | Windows 已实现；Unix socket 有基础实现 |
| 签名授权对话框 | Slint 跨平台 UI 已实现 |
| PIN 解锁 | 已实现，后续需迁移到 envelope encryption 模型 |
| Windows Hello | 已有实现，后续需迁移到 envelope encryption 模型 |
| IPC 控制命令 | Windows 已实现；Linux/macOS 待补独立 control socket |
| Local Key Cache | 已实现旧模型；目标模型见 ADR |
| 标准平台存储目录 | 待实现；当前代码仍使用 exe 同目录 |
| 自启动 | Windows 已实现；macOS/Linux 待实现 |
| Shell integration | 待实现 `sshwarden env` |
| macOS native unlock | 设计已确认，待实现 |
| Linux native unlock | 设计已确认，待实现 |

设计权威记录见：

- [`CONTEXT.md`](CONTEXT.md) — 项目领域语言
- [`docs/adr/`](docs/adr/) — 架构决策记录

`llmdoc/` 中包含历史分析和 Bitwarden Desktop 参考资料，不代表 SSHWarden 当前支持状态。

## 核心概念

### Bitwarden Vault

Bitwarden Vault 是 SSH Key 的权威来源。SSHWarden 成功 sync 后，运行时 key set 应镜像 Bitwarden 中当前未删除、未归档的 SSH Key。

### Local Key Cache

SSHWarden 会维护一个本地加密 SSH Key 快照，让 Remembered Device 在 Bitwarden 不可达时仍可解锁并签名。

目标模型是 envelope encryption：

```text
Local Cache Key -> 加密 SSH keys

PIN / Windows Hello / macOS Keychain / Linux Secret Service -> 解锁 Local Cache Key
```

这允许 sync 成功后刷新本地缓存，而不需要长期保存用户 PIN。

### Lock / Unlock / Forget

- **Lock**：阻止签名并清除本地缓存刷新能力；Key Identity 仍可列出。
- **Unlock**：用 PIN 或平台原生方法恢复签名能力。
- **Forget**：删除本机记住的 key/session/native unlock material，下次必须重新登录 Bitwarden。

### Signing Authorization

签名请求和解锁是两个步骤：

1. 如果 SSHWarden 已锁定，Signing Request 可以触发 Unlock。
2. Unlock 成功后，Signing Request 仍可能需要用户 Authorization。
3. Key List Request 不触发 Unlock；锁定状态下可以列出 Key Identity。

## 目标平台

SSHWarden 的一等支持平台目标是：

- Windows 10/11
- Linux 桌面会话
- macOS 13+

不把 WSL、BSD、移动端、浏览器环境、纯 headless server 作为 baseline 支持目标。

## 计划中的 baseline 能力

跨平台 baseline 应在所有一等平台上提供：

- Bitwarden 登录和 SSH Key sync
- 本地 SSH Agent endpoint
- PIN Unlock
- Signing Request 授权对话框
- Lock / Unlock / Forget
- Local Key Cache
- Control Channel：`status`、`lock`、`unlock`、`sync`、`set-pin` 等控制命令
- Shell Integration：`sshwarden env`
- Startup Integration：登录桌面会话后自动启动
- `status` 简洁状态报告
- `doctor` 跨平台诊断检查

平台原生 unlock 是 baseline 之后的增强路线：

1. Windows Hello
2. macOS Keychain + Touch ID / user presence
3. Linux Secret Service-compatible keyring

## 当前使用方式

> 以下命令反映当前实现，后续 CLI 会随 baseline 设计调整。

### 配置

复制配置示例：

```bash
cp config.toml.example config.toml
```

编辑 `config.toml`，填写 Bitwarden 邮箱、服务器地址等配置。

### 启动 daemon

```bash
sshwarden daemon
```

或直接运行：

```bash
sshwarden
```

### 登录 / 同步 keys

```bash
sshwarden login
sshwarden keys
sshwarden sync
```

### 生成 SSH key selector / SSH config snippet

当 Bitwarden 里有多把 SSH Key 时，OpenSSH 可能会因为 `MaxAuthTries` 在尝试完所有 agent key 前断开连接。SSHWarden 支持生成公开 `.pub` selector 文件，并配合 `IdentitiesOnly yes` 限定每个 Host 使用指定 key：

```bash
# 打印建议的 Host snippet，同时刷新 selector .pub 文件
sshwarden ssh-config

# 写入托管 include 文件并确保 ~/.ssh/config Include 它
sshwarden ssh-config --write
```

selector 文件只包含公钥，默认位于 SSHWarden 配置目录的 `keys/` 子目录。

### 锁定 / 解锁

```bash
sshwarden lock
sshwarden unlock --pin
sshwarden unlock --hello      # Windows 当前可用
sshwarden unlock --password
```

### 设置 PIN

```bash
sshwarden set-pin
```

### 查看状态

```bash
sshwarden status
```

### Windows 自启动

```bash
sshwarden daemon --install
sshwarden daemon --uninstall
```

Linux/macOS 自启动安装仍待实现。

## 与官方 Bitwarden Desktop 的关系

Bitwarden Desktop 已经提供 SSH Agent，但它依赖完整 Electron 桌面客户端。SSHWarden 的目标是提供一个更轻量的独立 agent。

设计上参考官方实现：

- SSH Key 来自 Bitwarden Vault
- SSH Agent 的运行时 key set 是 vault 的投影
- 签名请求需要授权
- Agent forwarding 始终需要显式授权
- 锁定状态下可以保留可列出的 Key Identity

不同点：

- SSHWarden 不依赖 Electron/Angular
- SSHWarden 需要自己维护轻量 Local Key Cache
- SSHWarden 的跨平台 daemon/control/startup/shell integration 独立实现

## 技术栈

- Rust
- Tokio
- Clap
- Slint
- bitwarden-russh
- reqwest
- tokio-tungstenite
- AES-256-CBC + HMAC-SHA256
- Argon2id
- zeroize

## 构建

```bash
cargo build --release
```

更多构建信息见 [`BUILD.md`](BUILD.md)。

## 许可证

本项目基于 Bitwarden clients 的部分代码和设计参考开发，遵循 GPL-3.0 许可证。

- License: GPL-3.0
- Upstream: https://github.com/bitwarden/clients
- Bitwarden 是 Bitwarden Inc. 的注册商标。本项目与 Bitwarden Inc. 无关联。
