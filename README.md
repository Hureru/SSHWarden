# SSHWarden

[![Build and Test](https://github.com/Hureru/SSHWarden/actions/workflows/build.yml/badge.svg)](https://github.com/Hureru/SSHWarden/actions/workflows/build.yml)
[![Release](https://github.com/Hureru/SSHWarden/actions/workflows/release.yml/badge.svg)](https://github.com/Hureru/SSHWarden/actions/workflows/release.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

一个独立的命令行 SSH Agent 守护进程，从 Bitwarden 密码库获取 SSH 密钥，替代系统 OpenSSH Agent。

> **注意**: 本项目基于 [Bitwarden clients](https://github.com/bitwarden/clients) 的部分代码开发，遵循 GPL-3.0 许可证。Bitwarden 是 Bitwarden Inc. 的注册商标。

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

## 安装

### 从 Release 下载（推荐）

前往 [Releases](https://github.com/Hureru/SSHWarden/releases) 页面下载最新版本：

- **Windows**: `sshwarden-x.x.x-windows-x64.zip`
- **Linux**: `sshwarden-x.x.x-linux-x64.tar.gz`
- **macOS**: `sshwarden-x.x.x-macos-x64.tar.gz`

### 从源码构建

```bash
git clone https://github.com/Hureru/SSHWarden.git
cd SSHWarden
cargo build --release
```

详细构建说明请参阅 [BUILD.md](BUILD.md)

## 快速开始

### 配置

1. 复制配置文件示例：
```bash
cp config.toml.example config.toml
```

2. 编辑 `config.toml`，填写你的 Bitwarden 邮箱和其他配置。

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

本项目基于 [Bitwarden clients](https://github.com/bitwarden/clients) 开发，遵循 GPL-3.0 许可证。

- **许可证**: GPL-3.0
- **上游项目**: [Bitwarden clients](https://github.com/bitwarden/clients)
- **商标**: Bitwarden 是 Bitwarden Inc. 的注册商标，本项目与 Bitwarden Inc. 无关联

## 安全说明

- 所有敏感数据（config.toml, vault.enc）都已在 .gitignore 中排除
- 密钥使用 AES-256-CBC + HMAC-SHA256 加密
- PIN 使用 Argon2id 进行密钥派生
- 支持 Windows Hello 生物识别保护

## 贡献

欢迎提交 Issue 和 Pull Request！
