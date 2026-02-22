# SSH Agent 密钥管理与加密架构

## 1. Identity

- **What it is:** Bitwarden 桌面端 SSH Agent 的密钥管理子系统，负责 SSH 私钥的解析、存储、签名和生命周期管理。
- **Purpose:** 将 Bitwarden 密码库中的 SSH 密钥安全地提供给本地 SSH 客户端，同时通过用户审批机制控制签名操作。

## 2. Core Components

- `desktop/desktop_native/core/src/ssh_agent/mod.rs` (`BitwardenDesktopAgent`, `BitwardenSshKey`, `parse_key_safe`, `set_keys`, `lock`, `clear_keys`): 核心 SSH Agent 实现。维护 `KeyStore<BitwardenSshKey>`（`HashMap<Vec<u8>, BitwardenSshKey>`，以公钥字节为键）。实现 `bitwarden_russh::ssh_agent::Agent` trait 的 `confirm`/`can_list`/`set_sessionbind_info` 方法。
- `desktop/desktop_native/core/src/ssh_agent/request_parser.rs` (`parse_request`, `SshAgentSignRequest`): 解析签名请求数据，区分 SSHSIG 请求（检测 `"SSHSIG"` magic header，提取 namespace 如 `"git"`）和普通 SSH 认证签名请求。
- `desktop/desktop_native/ssh_agent/src/crypto/mod.rs` (`SSHKeyData`, `PrivateKey`, `PublicKey`): 独立的 `ssh_agent` crate 中的加密原语类型定义。当前标记为 `dead_code`，是计划中的抽象层，尚未被运行时 Agent 消费。
- `desktop/desktop_native/napi/src/sshagent.rs` (`serve`, `set_keys`, `lock`, `clear_keys`): N-API 绑定层，将 Rust SSH Agent 暴露给 Electron 主进程。
- `desktop/src/autofill/services/ssh-agent.service.ts` (`SshAgentService`): Angular 渲染进程服务，负责每 1 秒定时将密码库中 `CipherType.SshKey` 类型的密钥同步到 Rust 原生层。
- `desktop/desktop_native/core/src/lib.rs` (`ZeroAlloc`): 全局内存分配器，在内存释放时自动清零，防止密钥残留在已释放的堆内存中。

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 密钥加载流程

- **1. 定时同步:** 渲染进程 `SshAgentService` 每 1 秒触发，从 `CipherService.getAllDecrypted()` 获取所有解密后的密码库条目，过滤 `CipherType.SshKey && !isDeleted`。参见 `desktop/src/autofill/services/ssh-agent.service.ts`。
- **2. IPC 传递:** 过滤出的 `{privateKey, name, cipherId}` 元组通过 Electron IPC -> preload bridge -> 主进程 -> NAPI 传递到 Rust 层。参见 `desktop/desktop_native/napi/src/sshagent.rs` (`set_keys`)。
- **3. PEM 解析:** `BitwardenDesktopAgent::set_keys()` 接收 `Vec<(String, String, String)>` 元组，调用 `parse_key_safe()` 使用 `ssh_key::private::PrivateKey::from_openssh()` 解析 OpenSSH PEM 字符串。参见 `desktop/desktop_native/core/src/ssh_agent/mod.rs:215-254`。
- **4. 存储:** 解析成功的密钥以公钥字节 (`private_key.public_key().to_bytes()`) 为键存入 `KeyStore`（`HashMap<Vec<u8>, BitwardenSshKey>`）。

### 3.2 签名流程

- **1. 请求到达:** SSH 客户端通过 socket/pipe 发送 `SSH_AGENTC_SIGN_REQUEST`，由 `bitwarden_russh::ssh_agent::serve()` 处理。
- **2. 请求解析:** `BitwardenDesktopAgent::confirm()` 调用 `request_parser::parse_request()` 解析请求数据，检测 SSHSIG magic header 并提取 namespace。参见 `desktop/desktop_native/core/src/ssh_agent/request_parser.rs:17-41`。
- **3. 用户审批:** 通过 tokio mpsc channel 将 `SshAgentUIRequest` 发送到 UI 层，等待 broadcast channel 返回匹配 `request_id` 的审批结果。参见 `desktop/desktop_native/core/src/ssh_agent/mod.rs:84-136`。
- **4. 签名执行:** 审批通过后，`bitwarden_russh` 调用 `BitwardenSshKey::private_key()` 获取 `Box<dyn ssh_key::SigningKey>`，执行 `try_sign(data)`。

### 3.3 锁定与清除

- **Soft Lock (`lock`):** 遍历 keystore，将每个 `BitwardenSshKey.private_key` 设为 `None`。公钥条目保留，可列出但无法签名。参见 `mod.rs:256-273`。
- **Clear Keys (`clear_keys`):** 完全清空 keystore HashMap，并设置 `needs_unlock = true`，后续密钥列出操作需要用户交互。参见 `mod.rs:275-282`。
- **账户切换:** 渲染进程清空内存中的授权缓存并调用 `clearKeys()`。

## 4. Design Rationale

- **支持的算法:** 仅 Ed25519 和 RSA（`rsa-sha2-512`）。ECDSA 不支持（跟踪号 PM-29894）。
- **`ssh_agent` 独立 crate vs `desktop_core::ssh_agent`:** 前者 (`desktop/desktop_native/ssh_agent/`) 定义了原始加密类型但全部标记 `dead_code`，是计划中的后续 PR 抽象层；后者是实际运行时实现。
- **`needs_unlock` 语义:** 初始为 `true`，`set_keys()` 后重设为 `true`。确保在首次解锁前或密钥更新后，即使列出公钥也需要用户交互确认。
- **SSHSIG namespace:** 允许 UI 区分 git 签名（namespace `"git"`）、文件签名和常规 SSH 认证，向用户展示不同的操作描述。
