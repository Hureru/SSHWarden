# SSH Agent IPC 通道参考

## 1. Core Summary

SSH Agent 的进程间通信使用 7 个 IPC 通道：6 个 Renderer->Main 方向的 `ipcRenderer.invoke` / `ipcMain.handle` 通道，以及 1 个 Main->Renderer 方向的通过通用 `messagingService` Electron 通道发送的命令消息。Main 进程使用 50ms 轮询间隔（60 秒超时）等待 Renderer 的签名审批响应。

## 2. IPC 通道清单

| 通道名称 | 方向 | 传输模式 | 用途 | 数据格式 |
|---|---|---|---|---|
| `sshagent.init` | Renderer -> Main | `invoke/handle` | 初始化原生 SSH Agent 服务器 | 无参数 |
| `sshagent.isloaded` | Renderer -> Main | `invoke/handle` | 检查 `agentState` 是否非 null | 返回 `boolean` |
| `sshagent.setkeys` | Renderer -> Main | `invoke/handle` | 推送解密后的 SSH 私钥到原生层 | `{name, privateKey, cipherId}[]` |
| `sshagent.signrequestresponse` | Renderer -> Main | `invoke/handle` | 发送用户批准/拒绝决定 | `{requestId: number, accepted: boolean}` |
| `sshagent.lock` | Renderer -> Main | `invoke/handle` | 清除私钥但保留公钥元数据 | 无参数 |
| `sshagent.clearkeys` | Renderer -> Main | `invoke/handle` | 完全清除所有密钥 | 无参数 |
| `sshagent.signrequest` | Main -> Renderer | 通过 `messagingService` | 通知 Renderer 有外部签名请求 | `{cipherId, isListRequest, requestId, processName, isAgentForwarding, namespace}` |

## 3. Main->Renderer 消息传递模式

`sshagent.signrequest` 消息不使用专用 IPC 通道，而是通过通用的 `messagingService` 广播通道发送：
- Main 进程调用 `messagingService.send("sshagent.signrequest", payload)`。
- `ElectronMainMessagingService` 将其序列化为 `webContents.send("messagingService", message)`。
- Renderer 端的 `MessageListener` 通过 `ipcRenderer.on("messagingService", ...)` 监听并根据 `command` 字段分发。
- `SshAgentService` 通过 `messages$(new CommandDefinition("sshagent.signrequest"))` 订阅该命令。

## 4. Main 进程轮询机制

`MainSshAgentService` 在收到 Rust NAPI 回调后，使用 RxJS `race` 实现带超时的轮询等待：
- **轮询间隔:** 50ms (`REQUEST_POLL_INTERVAL`)。
- **超时时间:** 60 秒 (`SIGN_TIMEOUT`)。
- **响应存储:** `requestResponses: AgentResponse[]`，每项包含 `{requestId, accepted, timestamp}`。
- **清理策略:** 每次新请求到达时，移除所有超过 60 秒的陈旧响应。

## 5. Source of Truth

- **Preload 桥接定义:** `desktop/src/platform/preload.ts:52-70` -- 6 个 Renderer->Main IPC 方法的完整定义。
- **Main 进程处理器:** `desktop/src/autofill/main/main-ssh-agent.service.ts` -- 所有 `ipcMain.handle` 注册和轮询逻辑。
- **Renderer 监听器:** `desktop/src/autofill/services/ssh-agent.service.ts:79-201` -- `sshagent.signrequest` 消息处理和 IPC 调用。
- **通用消息服务:** `desktop/src/services/electron-main-messaging.service.ts` (`ElectronMainMessagingService`) -- Main->Renderer `messagingService` 通道的实现。
- **相关架构文档:** `/llmdoc/architecture/ssh-agent-authorization-flow.md` -- 完整授权决策流程。
