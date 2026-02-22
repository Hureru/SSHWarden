# Architecture of Windows Hello Unlock in SSHWarden

## 1. Identity

- **What it is:** SSHWarden 的 Windows Hello 解锁模块，提供两条路径：UserConsentVerifier（UV，仅验证身份）和 KeyCredentialManager 签名路径（持久化密钥派生）。
- **Purpose:** 在密码库锁定时，通过 Windows Hello（指纹/面部/PIN）验证用户身份并恢复 SSH 密钥。签名路径支持跨守护进程重启的持久化解锁。

## 2. Core Components

- `crates/sshwarden-ui/src/unlock/mod.rs` (`UnlockResult`): 解锁结果枚举（Verified/Cancelled/NotAvailable/Failed），条件编译分派。
- `crates/sshwarden-ui/src/unlock/windows.rs` (`prompt_windows_hello`, `show_windows_hello`, `focus_and_center_security_prompt_pub`): Windows Hello UV 路径，使用 `UserConsentVerifier` API。
- `crates/sshwarden-ui/src/unlock/hello_crypto.rs` (`hello_derive_key`, `hello_encrypt_keys`, `hello_decrypt_keys`, `hello_available`, `credential_set`, `credential_get`, `credential_delete`, `credential_exists`): Windows Hello 签名路径 + Windows Credential Manager 加密缓存。
- `src/main.rs` (`handle_ui_request`, `handle_control_command`, `try_hello_unlock`, `finish_unlock_with_json`): 多个调用入口和共用的解锁完成逻辑。

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 签名路径解锁 (KeyCredentialManager)

- **1. 触发:** CLI `sshwarden unlock --hello` 发送 `unlock-hello` 命令，或 `unlock` 命令自动优先尝试签名路径，或 SSH 请求触发自动解锁。参见 `src/main.rs:608-670` (UnlockHello), `src/main.rs:547-578` (Unlock 自动尝试), `src/main.rs:1026-1070` (handle_ui_request).
- **2. 读取 challenge:** 从 `vault_file_data` 读取 `hello_challenge`（Base64 编码的 16 字节）和 `email`. 参见 `src/main.rs:615-646`.
- **3. spawn_blocking:** 调用 `try_hello_unlock(challenge, email)` 在阻塞线程池执行. 参见 `src/main.rs:648-650`.
- **4. 读取 Credential Manager:** `credential_get("SSHWarden", email)` 获取 Hello 加密的密钥缓存密文. 参见 `src/main.rs:948-952`, `crates/sshwarden-ui/src/unlock/hello_crypto.rs:146-182`.
- **5. Hello 密钥派生:** `hello_derive_key(challenge)` 创建/打开 "SSHWardenBiometrics" KeyCredential，签名 challenge，SHA-256(signature) 得到 32 字节 enc_key，再派生 mac_key = SHA-256("sshwarden-hello-mac" || enc_key). 参见 `crates/sshwarden-ui/src/unlock/hello_crypto.rs:33-90`.
- **6. AES 解密:** `hello_decrypt_keys(enc_string, challenge)` 用派生的对称密钥解密 EncString 得到密钥 JSON. 参见 `crates/sshwarden-ui/src/unlock/hello_crypto.rs:230-246`.
- **7. 完成解锁:** `finish_unlock_with_json()` 解析 JSON、更新 key_names、加载到 Agent、清除锁定标志. 参见 `src/main.rs:956-991`.

### 3.2 UV 路径解锁 (UserConsentVerifier)

- **1. 触发:** CLI `sshwarden unlock`（签名路径失败后降级），或 SSH 请求自动解锁（签名路径失败后降级）。参见 `src/main.rs:581-606`, `src/main.rs:1073-1095`.
- **2. spawn_blocking:** `prompt_windows_hello()` 通过 `tokio::task::spawn_blocking` 调用 `show_windows_hello()`. 参见 `crates/sshwarden-ui/src/unlock/windows.rs`.
- **3. 可用性检查:** `UserConsentVerifier::CheckAvailabilityAsync()` 检查设备是否支持 Windows Hello.
- **4. 请求验证:** `UserConsentVerifier::RequestVerificationAsync(&message)` 弹出系统验证对话框.
- **5. 结果处理:** Verified -> 从 `cached_key_tuples` 内存缓存重新加载密钥 -> 清除锁定标志。参见 `src/main.rs:584-596`.

### 3.3 SSH 请求自动解锁优先级

- **1. Hello 签名路径:** 检查 vault_file_data 中的 hello_challenge，尝试 `try_hello_unlock()`. 参见 `src/main.rs:1026-1070`.
- **2. Hello UV 降级:** 签名路径失败后，尝试 `prompt_windows_hello()` UV 验证. 参见 `src/main.rs:1073-1095`.
- **3. 拒绝:** 两者均失败则拒绝当前 SSH 请求. 参见 `src/main.rs:1097-1100`.

## 4. Design Rationale

- **双路径互补:** UV 路径仅验证身份，依赖进程内存中的 `cached_key_tuples`，进程重启后失效。签名路径通过 KeyCredentialManager 派生加密密钥 + Credential Manager 持久化密文，支持跨重启解锁。
- **签名路径优先:** 自动解锁时优先尝试签名路径（可持久化），失败后降级到 UV 路径（需内存缓存）。
- **Focus helper:** 签名路径和 UV 路径都使用后台线程持续调用 focus helper，确保安全提示窗口前置可见。
- **spawn_blocking:** WinRT 同步 API（`.get()` 阻塞等待 `IAsyncOperation`）不能在 tokio 异步运行时中直接调用，必须在阻塞线程池执行。
