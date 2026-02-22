# SSH Agent 数据流与通信架构

## 1. Identity

- **What it is:** SSH Agent 系统中所有数据流路径的完整描述，包括签名请求流、IPC 通道、密钥同步机制和 NAPI 桥接模式。
- **Purpose:** 为 LLM Agent 提供从 SSH 客户端连接到最终响应返回的完整追踪路径。

## 2. Core Components

- `desktop/desktop_native/core/src/ssh_agent/mod.rs` (`BitwardenDesktopAgent`, `confirm`, `can_list`, `set_keys`, `lock`, `clear_keys`): Agent trait 实现，管理密钥存储和 UI 请求/响应通道。
- `desktop/desktop_native/napi/src/sshagent.rs` (`serve`, `setKeys`, `lock`, `clearKeys`): NAPI 绑定层，使用 `ThreadsafeFunction<SshUIRequest, Promise<bool>>` 桥接 Rust 异步和 JS 回调。
- `desktop/src/autofill/main/main-ssh-agent.service.ts` (`MainSshAgentService`): Electron 主进程服务，注册 6 个 `ipcMain.handle` 并管理 `requestResponses` 轮询数组。
- `desktop/src/autofill/services/ssh-agent.service.ts` (`SshAgentService`): Angular renderer 服务，处理密码库状态、密钥过滤、用户审批对话框和 1 秒定时器密钥同步。
- `desktop/src/platform/preload.ts` (`sshAgent`): Preload 桥接，将 renderer 的 `ipc.platform.sshAgent.*` 调用映射为 `ipcRenderer.invoke("sshagent.*")`。
- `desktop/desktop_native/core/src/ssh_agent/request_parser.rs` (`parse_request`): 解析签名请求，区分 SSHSIG (含 namespace) 和普通 SSH 认证。
- `desktop/desktop_native/core/src/ssh_agent/peerinfo/gather.rs` (`get_peer_info`): 通过 `sysinfo` crate 从 PID 解析进程名。

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 完整签名请求流（13 步）

```
SSH Client --> [Socket] --> Rust Agent --> [NAPI] --> Main Process --> [IPC] --> Renderer
Renderer --> [IPC] --> Main Process --> [Poll] --> NAPI Promise --> Rust Agent --> [Socket] --> SSH Client
```

- **Step 1 -- SSH 客户端连接**: 外部 SSH 客户端连接到平台 socket。Windows: `\\.\pipe\openssh-ssh-agent` (`desktop/desktop_native/core/src/ssh_agent/named_pipe_listener_stream.rs:36-80`)；Unix: `~/.bitwarden-ssh-agent.sock` (`desktop/desktop_native/core/src/ssh_agent/unix.rs:18-42`)。
- **Step 2 -- 客户端进程识别**: 平台 listener 提取客户端 PID（Windows: `GetNamedPipeClientProcessId`；Unix: `peer_cred()`），然后调用 `peerinfo::gather::get_peer_info(pid)` 解析进程名。
- **Step 3 -- SSH 协议处理**: `bitwarden_russh::ssh_agent::serve()` 处理 SSH Agent 协议消息，对签名请求调用 `BitwardenDesktopAgent::confirm()` (`desktop/desktop_native/core/src/ssh_agent/mod.rs:84-136`)。
- **Step 4 -- UI 请求派发**: `confirm()` 调用 `request_parser::parse_request()` 检测 SSHSIG namespace，递增 `request_id`，通过 `show_ui_request_tx` (mpsc channel) 发送 `SshAgentUIRequest`，然后在 `get_ui_response_rx` (broadcast channel) 上等待。
- **Step 5 -- NAPI 回调到 Node.js**: `napi/src/sshagent.rs:52-106` 中的 tokio task 接收 `SshAgentUIRequest`，通过 `ThreadsafeFunction.call_with_return_value()` 以 `ThreadsafeFunctionCallMode::Blocking` 调用 JS 回调，获得 `Promise<bool>`。
- **Step 6 -- MainSshAgentService 转发**: JS 回调 (`main-ssh-agent.service.ts:40-84`) 递增自身 `request_id`，调用 `messagingService.send("sshagent.signrequest", {...})` 将请求发往 renderer。
- **Step 7 -- 消息到达 Renderer**: `ElectronMainMessagingService.send()` 通过 `webContents.send("messagingService", message)` 发送。Renderer 的 `MessageListener` 通过 `ipcRenderer.on("messagingService", ...)` 接收并分发。
- **Step 8 -- Renderer 处理请求**: `SshAgentService` (`ssh-agent.service.ts:79-201`) 订阅 `CommandDefinition("sshagent.signrequest")`。检查 SSH agent 是否启用、密码库是否解锁（未解锁则等待最多 60 秒）、获取解密后的 ciphers、根据 `SshAgentPromptType` 决定是否弹出 `ApproveSshRequestComponent` 对话框。
- **Step 9 -- 响应发回**: Renderer 调用 `ipc.platform.sshAgent.signRequestResponse(requestId, accepted)` -> `ipcRenderer.invoke("sshagent.signrequestresponse", {requestId, accepted})`。
- **Step 10 -- 主进程记录响应**: `ipcMain.handle("sshagent.signrequestresponse")` 将 `{requestId, accepted, timestamp}` push 到 `requestResponses` 数组 (`main-ssh-agent.service.ts:101-106`)。
- **Step 11 -- NAPI 回调 resolve**: 主进程的 JS 回调每 50ms 轮询 `requestResponses`（60 秒超时）。匹配后返回 `accepted` boolean，resolve `Promise<bool>` (`main-ssh-agent.service.ts:57-83`)。
- **Step 12 -- Rust 接收响应**: NAPI 层 await Promise 完成后，通过 `auth_response_tx` broadcast channel 发送 `(request_id, result)` (`napi/src/sshagent.rs:100-104`)。
- **Step 13 -- Agent confirm() 返回**: `BitwardenDesktopAgent::confirm()` 从 broadcast channel 收到匹配的 `(id, response)`，返回 boolean 给 `bitwarden_russh`，完成或拒绝 SSH 签名操作 (`mod.rs:130-135`)。

### 3.2 IPC 通道清单（7 个通道）

| 通道名 | 方向 | 传输方式 | 用途 |
|--------|------|----------|------|
| `sshagent.init` | Renderer -> Main | `ipcRenderer.invoke` | 初始化原生 SSH agent 服务器 |
| `sshagent.isloaded` | Renderer -> Main | `ipcRenderer.invoke` | 检查 `agentState` 是否已初始化 |
| `sshagent.setkeys` | Renderer -> Main | `ipcRenderer.invoke` | 推送解密后的 SSH 私钥到原生 agent |
| `sshagent.signrequestresponse` | Renderer -> Main | `ipcRenderer.invoke` | 返回用户审批/拒绝决定 |
| `sshagent.lock` | Renderer -> Main | `ipcRenderer.invoke` | 清除 keystore 中的私钥（保留公钥） |
| `sshagent.clearkeys` | Renderer -> Main | `ipcRenderer.invoke` | 完全清空 keystore |
| `sshagent.signrequest` | Main -> Renderer | `messagingService.send` | 通知 renderer 有新的签名请求 |

### 3.3 定期密钥同步机制

`SshAgentService` (`ssh-agent.service.ts:226-265`) 使用 `combineLatest([timer(0, 1000), sshAgentEnabled$])` 创建 1 秒间隔定时器：

1. 检查 `sshAgentEnabled$` -- 禁用时调用 `clearKeys()`
2. 获取活跃账户和认证状态 -- 未解锁则跳过
3. 调用 `cipherService.getAllDecrypted(userId)` -- 若返回 null 则调用 `lock()`
4. 过滤 `CipherType.SshKey`（排除已删除项），提取 `{name, privateKey, cipherId}`
5. 调用 `ipc.platform.sshAgent.setKeys(keys)` 推送到 Rust 层

账户切换时（`accountService.activeAccount$.pipe(skip(1))`）清空 `authorizedSshKeys` 缓存并调用 `clearKeys()`。

### 3.4 NAPI 桥接模式

`napi/src/sshagent.rs:42-116` 中的 `serve()` 函数建立双向异步桥接：

- **请求通道**: `tokio::sync::mpsc::channel<SshAgentUIRequest>(32)` -- Rust agent 向 NAPI 层发送 UI 请求
- **响应通道**: `tokio::sync::broadcast::channel<(u32, bool)>(32)` -- NAPI 层向 Rust agent 广播审批结果
- **JS 回调**: `ThreadsafeFunction<SshUIRequest, Promise<bool>>` -- NAPI 通过 `call_with_return_value` 调用 JS 回调，使用 `std::sync::mpsc::channel` 获取返回的 `Promise<bool>`，再 await 该 Promise
- **并发处理**: 每个 UI 请求 spawn 一个独立 tokio task，支持多个 SSH 客户端并发请求

## 4. Design Rationale

- **50ms 轮询而非事件回调**: `MainSshAgentService` 使用轮询而非直接回调，因为 NAPI 回调在主进程 JS 线程同步运行，而审批响应从 renderer 异步到达。
- **broadcast channel 匹配 request_id**: 使用 broadcast 而非 oneshot，因为同一个 receiver 需要持续接收多个响应，通过 `request_id` 匹配。
- **双重 60 秒超时**: renderer 等待密码库解锁 60 秒，主进程等待响应 60 秒，形成双层保护。
- **`needs_unlock` 标志**: 初始化后和 `set_keys()`/`clear_keys()` 后设为 `true`，确保密码库锁定后即使列出密钥也需要用户交互。
