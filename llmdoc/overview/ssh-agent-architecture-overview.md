# SSH Agent 整体架构

## 1. Identity

- **What it is:** Bitwarden Desktop 内置的 SSH Agent，作为系统 OpenSSH Agent 的替代品，从 Bitwarden 密码库中提供 SSH 密钥进行签名和认证。
- **Purpose:** 让用户无需单独管理 SSH 密钥文件，直接使用存储在 Bitwarden 密码库中的 SSH 密钥完成 SSH 认证和 Git 签名，并提供用户审批 UI。

## 2. High-Level Description

SSH Agent 采用**三层架构**，每层运行在不同的进程/运行时环境中：

1. **Rust 原生层** -- 实现 SSH Agent 协议服务器、密钥存储、平台 socket 监听和签名操作
2. **Electron 主进程层** -- 通过 NAPI 桥接 Rust 和 renderer，管理 IPC 通道和请求/响应轮询
3. **Angular Renderer 层** -- 处理业务逻辑（密码库状态、密钥同步、用户审批对话框）

外部 SSH 客户端（`ssh`、`git` 等）通过平台 socket 连接到 Rust 层，签名请求经三层传递到 UI 获取用户批准后返回。密钥每秒从密码库同步到 Rust 原生层。

## 3. 组件清单

### Rust 原生层
- `desktop/desktop_native/core/src/ssh_agent/mod.rs` (`BitwardenDesktopAgent`, `BitwardenSshKey`, `SshAgentUIRequest`) -- 核心 Agent 实现，密钥存储和 UI 通信通道
- `desktop/desktop_native/core/src/ssh_agent/windows.rs` -- Windows Named Pipe 服务器 (`\\.\pipe\openssh-ssh-agent`)
- `desktop/desktop_native/core/src/ssh_agent/unix.rs` -- Unix Domain Socket 服务器 (`~/.bitwarden-ssh-agent.sock`)
- `desktop/desktop_native/core/src/ssh_agent/named_pipe_listener_stream.rs` (`NamedPipeServerStream`) -- Windows 连接监听和客户端 PID 获取
- `desktop/desktop_native/core/src/ssh_agent/peercred_unix_listener_stream.rs` (`PeercredUnixListenerStream`) -- Unix 连接监听和 peer credential 提取
- `desktop/desktop_native/core/src/ssh_agent/request_parser.rs` (`parse_request`) -- 区分 SSHSIG（如 git 签名）和普通 SSH 认证请求
- `desktop/desktop_native/core/src/ssh_agent/peerinfo/` (`PeerInfo`, `get_peer_info`) -- 客户端进程识别

### NAPI 桥接层
- `desktop/desktop_native/napi/src/sshagent.rs` (`serve`, `setKeys`, `lock`, `clearKeys`) -- Rust-to-Node.js 绑定，使用 `ThreadsafeFunction` 和 `Promise<bool>` 回调模式

### Electron 主进程层
- `desktop/src/autofill/main/main-ssh-agent.service.ts` (`MainSshAgentService`) -- 注册 IPC handlers，桥接 NAPI 回调和 renderer 消息
- `desktop/src/main.ts` (line 293) -- 启动时实例化 `MainSshAgentService`

### Electron Renderer 层 (Angular)
- `desktop/src/autofill/services/ssh-agent.service.ts` (`SshAgentService`) -- 密钥同步、签名请求审批流程、密码库状态管理
- `desktop/src/autofill/components/approve-ssh-request.ts` (`ApproveSshRequestComponent`) -- 用户审批对话框
- `desktop/src/platform/preload.ts` (`sshAgent` object, lines 52-70) -- renderer-to-main IPC 桥接
- `desktop/src/app/services/init.service.ts` (line 63) -- 启动时调用 `sshAgentService.init()`

## 4. 层间交互概要

| 边界 | 机制 | 方向 |
|------|------|------|
| 外部 SSH 客户端 <-> Rust | Named Pipe (Win) / Unix Socket (Unix) | 双向 |
| Rust <-> Node.js 主进程 | NAPI `ThreadsafeFunction` + `Promise<bool>` | 双向 |
| 主进程 <-> Renderer | Electron IPC (`ipcMain.handle` / `ipcRenderer.invoke`) + `messagingService` | 双向 |
