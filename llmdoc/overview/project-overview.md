# SSHWarden -- Bitwarden SSH Agent

## 1. Identity

- **What it is:** 一个独立的命令行 SSH Agent 守护进程，从 Bitwarden 密码库获取 SSH 密钥，替代系统 OpenSSH Agent。
- **Purpose:** 解决 SSH 密钥分散管理问题：通过 Bitwarden 集中存储 SSH 私钥，结合 Windows Hello 生物识别、PIN 锁定和 Toast 通知授权，在安全与便利之间取得平衡。

## 2. High-Level Description

SSHWarden 是一个纯 Rust CLI 程序，以守护进程模式运行于 Windows Named Pipe (`\\.\pipe\openssh-ssh-agent`) 或 Unix Domain Socket 上。它在启动时通过 Bitwarden API 登录并同步密码库中的 SSH 密钥，然后作为标准 SSH Agent 服务外部 SSH 客户端。签名请求触发 Windows Toast 通知让用户授权/拒绝。支持自动锁定超时、Windows Hello 解锁（UserConsentVerifier UV 路径 + KeyCredentialManager 签名路径）、PIN 快速解锁、主密码重新登录解锁、IPC 控制通道和 vault.enc 密钥持久化。

## 3. Tech Stack

| Layer | Technology | Role |
|---|---|---|
| CLI & Main Loop | Rust + Clap + Tokio | 守护进程、CLI 子命令、异步主循环 |
| SSH Agent | `sshwarden-agent` + `bitwarden-russh` | SSH Agent 协议、密钥存储、Named Pipe/Unix Socket |
| Bitwarden API | `sshwarden-api` + reqwest | Bitwarden 登录、sync、密钥解密 |
| Crypto | `sshwarden-api::crypto` | AES-256-CBC+HMAC、Argon2id PIN 派生 |
| UI / Unlock | `sshwarden-ui` | Windows Toast 通知、Windows Hello UV、Hello 签名路径、MessageBox fallback |
| Config & Vault | `sshwarden-config` + TOML + JSON | 配置文件管理、vault.enc 持久化存储（全部在 exe 同目录） |
| IPC Control | `sshwarden-agent::control` | Named Pipe JSON 协议控制通道 |

## 4. Crate 结构

| Crate | 路径 | 职责 |
|---|---|---|
| `sshwarden` (bin) | `src/main.rs` | CLI 入口、守护进程主循环、命令分发 |
| `sshwarden-agent` | `crates/sshwarden-agent/` | SSH Agent 核心、IPC control server |
| `sshwarden-api` | `crates/sshwarden-api/` | Bitwarden API 客户端、加解密 |
| `sshwarden-ui` | `crates/sshwarden-ui/` | Toast 通知、Windows Hello 解锁（UV + 签名路径）、Credential Manager |
| `sshwarden-config` | `crates/sshwarden-config/` | TOML 配置管理、vault.enc 持久化文件、便携路径解析（exe 同目录） |

## 5. 实现阶段

| Phase | 状态 | 内容 |
|---|---|---|
| Phase 1 | Done | Bitwarden API 登录、sync、密钥解密 |
| Phase 2 | Done | SSH Agent 协议服务器、密钥存储、签名 |
| Phase 3 | Done | Windows Toast 通知授权、Windows Hello 解锁、锁定自动弹解锁 |
| Phase 4 | Done | IPC 控制通道、CLI 子命令、自动锁定、PIN 加解密、Sync |
| Phase 5 | Done | vault.enc 密钥持久化、Windows Hello 签名路径、三路径解锁（Hello/PIN/Password）、启动免密码 |

## 6. Key Design Decisions

- **完全便携模式**: 所有数据文件（config.toml、vault.enc、sshwarden.log、sshwarden.pid）都存放在 exe 同目录下，`config_dir()` 使用 `std::env::current_exe().parent()`，无需 `%APPDATA%` 或 `%LOCALAPPDATA%`。整个程序可随 exe 移动，无外部依赖路径。
- **独立 CLI**: 不依赖 Electron/Node.js，纯 Rust 二进制文件，轻量运行。
- **Toast 通知授权**: 使用 WinRT ToastNotification API 弹出系统通知，替代 GUI 窗口。
- **IPC 控制通道**: Named Pipe JSON 协议，允许 CLI 子命令与守护进程通信。
- **PIN 便捷解锁**: Argon2id 派生密钥加密内存中的密钥缓存，同时持久化到 vault.enc 文件。
- **vault.enc 持久化**: 守护进程重启后无需重新输入主密码，通过 PIN/Hello/Password 解锁即可恢复密钥。
- **Windows Hello 双路径**: UserConsentVerifier（仅验证身份，依赖内存缓存）+ KeyCredentialManager 签名路径（持久化加密密钥，跨重启可用）。
- **自动锁定**: 配置化的 `lock_timeout`（默认 3600 秒），60 秒检查间隔。
- **启动文件夹自启动**: `daemon --install` 在用户启动文件夹创建快捷方式（而非 Task Scheduler），确保守护进程在交互式桌面会话中运行，支持 Toast 通知和 Windows Hello 等所有 UI 交互。
