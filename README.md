# SSHWarden

一个独立的命令行 SSH Agent 守护进程，从 Bitwarden 密码库获取 SSH 密钥，替代系统 OpenSSH Agent。

## 特性

- 🔐 **集中管理**: 通过 Bitwarden 集中存储和管理 SSH 私钥
- 🔑 **Windows Hello**: 支持 Windows Hello 生物识别解锁
- 📌 **PIN 快速解锁**: 使用 PIN 码快速解锁密钥库
- 🔔 **Toast 通知**: SSH 签名请求通过 Windows Toast 通知授权
- 💾 **密钥持久化**: vault.enc 文件持久化加密密钥，重启后无需重新登录
- 🚀 **完全便携**: 所有数据文件存放在 exe 同目录，可随程序移动
- 🔒 **自动锁定**: 可配置的自动锁定超时机制

## 技术栈

- **语言**: Pure Rust
- **异步运行时**: Tokio
- **CLI 框架**: Clap
- **SSH Agent**: bitwarden-russh
- **Windows API**: WinRT (Toast 通知、Windows Hello)
- **加密**: AES-256-CBC + HMAC-SHA256, Argon2id

## 快速开始

### 构建

```bash
cargo build --release
```

### 使用

1. 启动守护进程：
```bash
sshwarden daemon
```

2. 设置 PIN（可选）：
```bash
sshwarden set-pin
```

3. 查看状态：
```bash
sshwarden status
```

4. 锁定/解锁：
```bash
sshwarden lock
sshwarden unlock --hello  # Windows Hello 解锁
sshwarden unlock --pin    # PIN 解锁
```

5. 安装自启动：
```bash
sshwarden daemon --install
```

## 架构

SSHWarden 采用模块化设计，包含以下 crate：

- `sshwarden` (bin): CLI 入口和守护进程主循环
- `sshwarden-agent`: SSH Agent 核心和 IPC 控制服务器
- `sshwarden-api`: Bitwarden API 客户端和加解密
- `sshwarden-ui`: Toast 通知和 Windows Hello 解锁
- `sshwarden-config`: 配置管理和 vault.enc 持久化

详细架构文档请参阅 `llmdoc/` 目录。

## 许可证

GPL-3.0

## 安全说明

- 所有敏感数据（config.toml, vault.enc）都已在 .gitignore 中排除
- 密钥使用 AES-256-CBC + HMAC-SHA256 加密
- PIN 使用 Argon2id 进行密钥派生
- 支持 Windows Hello 生物识别保护

## 贡献

欢迎提交 Issue 和 Pull Request！
