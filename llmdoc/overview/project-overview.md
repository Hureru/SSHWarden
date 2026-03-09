# SSHWarden -- Bitwarden SSH Agent

## 1. Identity

- **What it is:** 一个独立的命令行 SSH Agent 守护进程，从 Bitwarden 密码库获取 SSH 密钥，替代系统 OpenSSH Agent。
- **Purpose:** 解决 SSH 密钥分散管理问题：通过 Bitwarden 集中存储 SSH 私钥，结合 Windows Hello 生物识别、PIN 锁定和 Slint 授权对话框，在安全与便利之间取得平衡。

## 2. High-Level Description

SSHWarden 是一个 Rust CLI 程序，以守护进程模式运行于 Windows Named Pipe (`\\.\pipe\openssh-ssh-agent`) 或 Unix Domain Socket 上。采用双线程模型：主线程运行 Slint GUI 事件循环（处理 PIN 对话框），tokio 运行时在独立线程处理异步逻辑。启动时通过 Bitwarden API 登录并同步密码库中的 SSH 密钥，然后作为标准 SSH Agent 服务外部 SSH 客户端。签名请求触发 Slint 授权对话框让用户授权/拒绝。支持自动锁定超时、Windows Hello 解锁（KeyCredentialManager 签名路径）、PIN 快速解锁（Slint 跨平台对话框）、主密码重新登录解锁、IPC 控制通道和 vault.enc 密钥持久化。

## 3. Tech Stack

| Layer | Technology | Role |
|---|---|---|
| CLI & Main Loop | Rust + Clap + Tokio + Slint | 守护进程（双线程：Slint 主线程 + tokio 线程）、CLI 子命令 |
| SSH Agent | `sshwarden-agent` + `bitwarden-russh` | SSH Agent 协议、密钥存储、Named Pipe/Unix Socket |
| Bitwarden API | `sshwarden-api` + reqwest | Bitwarden 登录、sync、密钥解密 |
| Crypto | `sshwarden-api::crypto` | AES-256-CBC+HMAC、Argon2id PIN 派生 |
| UI / Unlock | `sshwarden-ui` + Slint + winit (via WinitWindowAccessor) | Windows Hello UV、Hello 签名路径、PIN 输入对话框（Slint 跨平台暗色窗口）、SSH 签名授权对话框（Slint 跨平台）、窗口居中+聚焦（slint_center_win + winit focus_window）、Credential Manager |
| Config & Vault | `sshwarden-config` + TOML + JSON | 配置文件管理、vault.enc 持久化存储（全部在 exe 同目录） |
| IPC Control | `sshwarden-agent::control` | Named Pipe JSON 协议控制通道 |

## 4. Crate 结构

| Crate | 路径 | 职责 |
|---|---|---|
| `sshwarden` (bin) | `src/main.rs` | CLI 入口、守护进程主循环、命令分发 |
| `sshwarden-agent` | `crates/sshwarden-agent/` | SSH Agent 核心、IPC control server |
| `sshwarden-api` | `crates/sshwarden-api/` | Bitwarden API 客户端、加解密 |
| `sshwarden-ui` | `crates/sshwarden-ui/` | SSH 签名授权对话框（Slint 跨平台）、Windows Hello 解锁（签名路径）、PIN 输入对话框（Slint 跨平台）、Credential Manager |
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
- **Toast 通知授权**: ~~使用 WinRT ToastNotification API 弹出系统通知，替代 GUI 窗口~~ 已替换为 Slint 跨平台授权对话框（Approve/Deny 按钮）。
- **IPC 控制通道**: Named Pipe JSON 协议，允许 CLI 子命令与守护进程通信。
- **PIN 便捷解锁**: Argon2id 派生密钥加密内存中的密钥缓存，同时持久化到 vault.enc 文件。
- **vault.enc 持久化**: 守护进程重启后无需重新输入主密码，通过 PIN/Hello/Password 解锁即可恢复密钥。
- **双线程架构**: 同步 `fn main()` 主线程运行 Slint 事件循环（PIN 对话框 + 授权对话框），tokio 运行时在独立线程。通过 `mpsc::channel<UIRequest>` + bridge 线程 + `slint::invoke_from_event_loop` 跨线程调度 UI 对话框。`UIRequest` 枚举统一了 `PinDialog` 和 `AuthDialog` 两种跨线程 UI 请求。
- **跨平台窗口居中+聚焦**: Slint 启用 `unstable-winit-030` feature，通过 `WinitWindowAccessor` 获取底层 winit 窗口，调用 `focus_window()` 确保对话框前置激活。居中使用 `slint_center_win` crate。两者均为跨平台实现，无 `#[cfg]` 条件编译。
- **Windows Hello 签名路径 + Slint PIN 对话框降级**: KeyCredentialManager 签名路径作为主要自动解锁方式（持久化加密密钥，跨重启可用）。Hello 不可用或失败时，弹出 Slint 跨平台 PIN 对话框（暗色主题、always-on-top）作为降级方案。PIN 对话框采用 validator 注入模式：验证逻辑通过闭包注入对话框内部，在后台线程执行 Argon2id 验证；错误 PIN 时对话框保持打开（抖动+红色提示），成功时缓存解密结果并关闭。UV（UserConsentVerifier）路径已从自动解锁流程中移除。
- **自动锁定**: 配置化的 `lock_timeout`（默认 3600 秒），60 秒检查间隔。
- **启动文件夹自启动**: `daemon --install` 在用户启动文件夹创建快捷方式（而非 Task Scheduler），确保守护进程在交互式桌面会话中运行，支持 Toast 通知和 Windows Hello 等所有 UI 交互。
