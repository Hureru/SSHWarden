# How to: SSH Agent 启动流程

从应用启动到 SSH Agent 服务器就绪的完整步骤。每一步标注涉及的文件和关键函数。

1. **Electron 主进程实例化 `MainSshAgentService`**: 应用启动时，`desktop/src/main.ts:293` 创建 `new MainSshAgentService(logService, messagingService)`。构造函数中注册 `ipcMain.handle("sshagent.init")` 和 `ipcMain.handle("sshagent.isloaded")` 两个 IPC handler (`desktop/src/autofill/main/main-ssh-agent.service.ts:28-35`)。此时原生 agent 尚未启动，`agentState` 为 null。

2. **Angular Renderer 初始化调用 `SshAgentService.init()`**: `desktop/src/app/services/init.service.ts:63` 在 Angular 应用初始化阶段调用 `this.sshAgentService.init()`。该方法订阅 `desktopSettingsService.sshAgentEnabled$`，当 SSH agent 启用且 `isLoaded()` 返回 false 时，调用 `ipc.platform.sshAgent.init()` (`desktop/src/autofill/services/ssh-agent.service.ts:63-76`)。

3. **Preload 桥接转发 IPC**: `ipc.platform.sshAgent.init()` 调用 `ipcRenderer.invoke("sshagent.init")` (`desktop/src/platform/preload.ts:53-55`)，该消息到达主进程的 `ipcMain.handle("sshagent.init")` handler。

4. **主进程调用 `sshagent.serve()` 启动原生 Agent**: `MainSshAgentService.init()` (`main-ssh-agent.service.ts:37-91`) 调用 NAPI 函数 `sshagent.serve(callback)`，传入一个 JS 回调函数用于接收签名请求。同时注册 `sshagent.setkeys`、`sshagent.signrequestresponse`、`sshagent.lock`、`sshagent.clearkeys` 四个额外的 IPC handler。

5. **NAPI 层建立通道并启动 Rust 服务器**: `desktop/desktop_native/napi/src/sshagent.rs:42-116` 中的 `serve()` 函数创建 `mpsc` channel（UI 请求）和 `broadcast` channel（UI 响应），spawn 一个 tokio task 接收 `SshAgentUIRequest` 并调用 JS `ThreadsafeFunction` 回调，然后调用 `BitwardenDesktopAgent::start_server(auth_request_tx, auth_response_rx)`。

6. **平台特定服务器启动**: `start_server()` 根据编译目标平台执行不同逻辑：
   - **Windows** (`desktop/desktop_native/core/src/ssh_agent/windows.rs`): 创建 `NamedPipeServerStream` 监听 `\\.\pipe\openssh-ssh-agent`，spawn tokio task 调用 `bitwarden_russh::ssh_agent::serve()`。
   - **Unix** (`desktop/desktop_native/core/src/ssh_agent/unix.rs`): 解析 socket 路径（`$BITWARDEN_SSH_AUTH_SOCK` 或 `$HOME/.bitwarden-ssh-agent.sock`），移除残留 socket 文件，bind `UnixListener`，设置 `0o600` 权限，包装为 `PeercredUnixListenerStream`，spawn tokio task 调用 `bitwarden_russh::ssh_agent::serve()`。

7. **验证启动成功**: `serve()` 返回 `Promise<SshAgentState>`，主进程的 `.then()` 回调保存 `agentState` 并记录日志 "SSH agent started" (`main-ssh-agent.service.ts:85-88`)。后续 renderer 的 1 秒定时器 (`ssh-agent.service.ts:226-265`) 开始周期性地将密码库中的 SSH 密钥同步到原生 agent。可通过 `ipc.platform.sshAgent.isLoaded()` 确认 `agentState != null`。
