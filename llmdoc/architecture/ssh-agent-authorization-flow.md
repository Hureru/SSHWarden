# SSH Agent 授权流程架构

## 1. Identity

- **What it is:** SSH Agent 请求授权与审批机制的完整架构，涵盖从外部 SSH 客户端请求到用户审批/拒绝的全链路决策流程。
- **Purpose:** 作为 SSH 密钥使用的安全网关，确保每次签名操作都经过恰当的用户授权检查。

## 2. Core Components

- `desktop/src/autofill/services/ssh-agent.service.ts` (`SshAgentService`, `needsAuthorization`, `rememberAuthorization`): Renderer 进程核心服务。管理授权决策树、vault 解锁等待、密钥同步、审批对话框触发，以及内存中的 `authorizedSshKeys` 缓存。
- `desktop/src/autofill/main/main-ssh-agent.service.ts` (`MainSshAgentService`, `AgentResponse`): Main 进程桥接服务。将 Rust 原生 SSH 请求通过 `messagingService` 转发给 Renderer，并通过 50ms 轮询等待响应（60 秒超时）。
- `desktop/src/autofill/components/approve-ssh-request.ts` (`ApproveSshRequestComponent`, `ApproveSshRequestParams`): Angular 审批对话框组件。根据 `namespace` 参数决定操作类型的 i18n 键值，返回 `true`（授权）或 `false`（拒绝）。
- `desktop/src/autofill/components/approve-ssh-request.html`: 对话框模板。显示 cipher 名称、应用程序名称、操作类型，以及可选的 Agent Forwarding 警告。
- `desktop/src/autofill/models/ssh-agent-setting.ts` (`SshAgentPromptType`): 枚举定义三种提示行为：`Always`、`Never`、`RememberUntilLock`。
- `desktop/src/platform/services/desktop-settings.service.ts` (`DesktopSettingsService`): 提供 `sshAgentEnabled$`（全局布尔值）和 `sshAgentPromptBehavior$`（每用户 `SshAgentPromptType`，默认 `Always`）。

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 授权决策树

- **1. 请求到达:** `MainSshAgentService` 收到 Rust 原生回调，通过 `messagingService.send("sshagent.signrequest", ...)` 转发到 Renderer。见 `desktop/src/autofill/main/main-ssh-agent.service.ts:37-91`。
- **2. 启用检查:** `SshAgentService` 检查 `sshAgentEnabled$`，若禁用则立即返回 `false`。见 `desktop/src/autofill/services/ssh-agent.service.ts:82-89`。
- **3. Vault 解锁门控:** 若 vault 已锁定，聚焦窗口 + 显示 toast 提示，等待最多 60 秒解锁。超时则返回 `false`。见 `desktop/src/autofill/services/ssh-agent.service.ts:98-137`。
- **4. List 请求 vs Sign 请求分流:**
  - **List 请求** (`isListRequest=true`): 自动批准。过滤所有 `CipherType.SshKey` 密钥，调用 `setKeys()` 同步到原生层，返回 `true`。见 `desktop/src/autofill/services/ssh-agent.service.ts:156-169`。
  - **Sign 请求**: 进入授权决策。见下方步骤 5。
- **5. `needsAuthorization()` 决策:**
  - `isForwarding === true` -> 始终需要授权（安全强制）。
  - `SshAgentPromptType.Never` -> 自动批准。
  - `SshAgentPromptType.Always` -> 始终弹出对话框。
  - `SshAgentPromptType.RememberUntilLock` -> 检查 `authorizedSshKeys[cipherId]` 是否存在，已缓存则跳过。
  - 见 `desktop/src/autofill/services/ssh-agent.service.ts:277-292`。
- **6. 审批对话框:** 若需授权，聚焦窗口并打开 `ApproveSshRequestComponent`。用户点击 "Authorize" 返回 `true`，"Deny" 返回 `false`。见 `desktop/src/autofill/services/ssh-agent.service.ts:178-197`。
- **7. 记忆授权:** 用户批准后，`rememberAuthorization(cipherId)` 将 cipher ID 和当前时间戳写入内存中的 `authorizedSshKeys` Record。见 `desktop/src/autofill/services/ssh-agent.service.ts:273-275`。

### 3.2 `authorizedSshKeys` 缓存生命周期

- **类型:** `Record<string, Date>` -- 纯内存存储，不持久化到磁盘。
- **写入:** `rememberAuthorization()` 在用户批准签名请求后写入。
- **清除时机:** (a) 活跃账户切换时（`activeAccount$.pipe(skip(1))`）; (b) 服务销毁时（`ngOnDestroy`）; (c) 应用重启时（隐式）。
- 见 `desktop/src/autofill/services/ssh-agent.service.ts:47,203-224,268-271`。

### 3.3 账户切换处理

- 监听 `accountService.activeAccount$.pipe(skip(1))`。
- 清空 `authorizedSshKeys = {}`。
- 调用 `ipc.platform.sshAgent.clearKeys()` 清除原生 keystore。
- 1 秒周期刷新循环自动从新活跃账户的 vault 重新加载密钥。
- 见 `desktop/src/autofill/services/ssh-agent.service.ts:203-224,226-265`。

### 3.4 设置模型

- `sshAgentEnabled$`: 全局 `KeyDefinition<boolean>`，所有账户共享。
- `sshAgentPromptBehavior$`: 每用户 `UserKeyDefinition<SshAgentPromptType>`，默认 `Always`，`clearOn: []`（永不自动清除）。
- 见 `desktop/src/platform/services/desktop-settings.service.ts:80-91,178-183`。

## 4. Design Rationale

- **Agent Forwarding 强制授权:** 转发请求来自远程设备，安全风险更高，因此无视用户的提示偏好设置，始终要求显式批准。
- **List/Sign 分流:** SSH 协议中密钥枚举（list）是低风险操作，自动批准并同步密钥；签名（sign）是高风险操作，需经过授权检查。
- **轮询机制:** Main 进程使用 50ms 轮询而非直接回调，因为 NAPI 回调在 Main 进程 JS 线程中同步运行，而审批响应从 Renderer 异步到达。
- **服务器无关性:** SSH Agent 不依赖任何服务器配置（cloud/self-hosted/EU），所有逻辑完全在本地桌面端执行。
