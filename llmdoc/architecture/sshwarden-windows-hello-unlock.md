# Architecture of Windows Hello Unlock in SSHWarden

## 1. Identity

- **What it is:** SSHWarden 的 Windows Hello 解锁模块，提供签名路径（KeyCredentialManager 持久化密钥派生）和 Slint PIN 对话框降级路径（跨平台）。
- **Purpose:** 在密码库锁定时，通过 Windows Hello（指纹/面部/PIN）验证用户身份并恢复 SSH 密钥。签名路径支持跨守护进程重启的持久化解锁。Hello 不可用时，通过 Slint 跨平台 PIN 对话框降级。

## 2. Core Components

- `crates/sshwarden-ui/src/unlock/mod.rs` (`UnlockResult`, `show_pin_dialog`, `request_pin_dialog`): 解锁结果枚举，导出 Slint PIN 对话框的跨线程通信函数.
- `crates/sshwarden-ui/src/unlock/slint_dialog.rs` (`show_pin_dialog`, `request_pin_dialog`): Slint PIN 对话框实现——`slint::slint!{}` 内联宏定义暗色主题窗口，`show_pin_dialog()` 在 Slint 主线程创建对话框，`request_pin_dialog()` 从 tokio 线程通过 `UIRequest::PinDialog` 异步请求.
- `crates/sshwarden-ui/src/unlock/windows.rs` (`prompt_windows_hello`, `focus_and_center_security_prompt_pub`): Windows Hello UV 路径（仅 CLI `unlock` 使用）+ 窗口居中辅助.
- `crates/sshwarden-ui/src/unlock/hello_crypto.rs` (`hello_derive_key`, `hello_encrypt_keys`, `hello_decrypt_keys`, `hello_available`, `credential_set`, `credential_get`, `credential_delete`, `credential_exists`): Windows Hello 签名路径 + Windows Credential Manager 加密缓存.
- `src/main.rs` (`handle_ui_request`, `handle_control_command`, `try_hello_unlock`, `finish_unlock_with_json`, `run_slint_event_loop`): 调用入口、解锁逻辑和 Slint 事件循环。Hello 签名路径成功后的授权改为 `request_authorization()` 通过 Slint 授权对话框。

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 签名路径解锁 (KeyCredentialManager)

- **1. 触发:** CLI `unlock --hello` 或 `unlock` 自动优先尝试签名路径，或 SSH 请求触发自动解锁. 参见 `src/main.rs:710-750` (Unlock), `src/main.rs:801-878` (UnlockHello), `src/main.rs:1350-1448` (handle_ui_request sign).
- **2. 读取 challenge:** 从 `vault_file_data` 读取 `hello_challenge` 和 `hello_encrypted`.
- **3. spawn_blocking:** `try_hello_unlock(challenge, hello_encrypted)` 在阻塞线程池执行.
- **4. Hello 密钥派生:** `hello_derive_key(challenge)` 签名 challenge，SHA-256 得到 enc_key. 参见 `crates/sshwarden-ui/src/unlock/hello_crypto.rs:33-90`.
- **5. AES 解密:** `hello_decrypt_keys()` 解密 EncString 得到密钥 JSON. 参见 `crates/sshwarden-ui/src/unlock/hello_crypto.rs:230-246`.
- **6. 完成解锁:** `finish_unlock_with_json()` 解析 JSON、加载到 Agent、清除锁定标志. 参见 `src/main.rs:1170-1204`.

### 3.2 Slint PIN 对话框降级路径

- **1. 触发:** Hello 签名路径失败后，在三个位置降级：ControlAction::Unlock (`src/main.rs:752-795`)、list 请求 (`src/main.rs:1280-1318`)、sign 请求 (`src/main.rs:1442-1527`).
- **2. 异步请求:** 调用 `request_pin_dialog(&ui_request_tx)` 向 Slint 主线程发送 `UIRequest::PinDialog`，通过 oneshot channel 等待结果. 参见 `crates/sshwarden-ui/src/unlock/slint_dialog.rs:114-135`.
- **3. Slint 调度:** bridge 线程接收 `UIRequest::PinDialog`，`slint::invoke_from_event_loop` 调用 `show_pin_dialog()` 在主线程创建 Slint 窗口. 参见 `src/main.rs:257-268`.
- **4. 用户交互:** Slint PIN 对话框（暗色主题、password input、always-on-top），用户输入 PIN 或取消. 参见 `crates/sshwarden-ui/src/unlock/slint_dialog.rs:3-49`.
- **5. PIN 解密:** 用户输入 PIN 后，从 `pin_encrypted_keys` 或 `vault_file_data` 读取密文，调用 `pin_decrypt()` 解密.
- **6. 授权对话框:** PIN 解锁成功后，若 `prompt_behavior` 要求授权，调用 `request_authorization()` 弹出 Slint 授权对话框. 参见 `src/main.rs:1509-1532`.
- **7. 完成解锁:** 解密成功后调用 `finish_unlock_with_json()` 加载密钥.

### 3.3 SSH 请求自动解锁优先级

- **1. Hello 签名路径:** 检查 vault_file_data 中的 hello_challenge，尝试 `try_hello_unlock()`.
- **2. Slint PIN 对话框降级:** 签名路径失败后，`request_pin_dialog()` 弹出 Slint PIN 对话框.
- **3. 拒绝:** 两者均失败则拒绝当前 SSH 请求.

## 4. Design Rationale

- **Slint 替代 Win32 PIN 对话框:** 使用 Slint GUI 框架（`slint::slint!{}` 内联宏）替代 ~460 行 Win32 原生 API 代码（Acrylic/DPI/字体/消息循环），实现跨平台 Windows/Linux/macOS 支持。
- **跨线程通信机制:** Slint 要求主线程运行事件循环。tokio 线程通过 `mpsc::channel<UIRequest>` 发送请求（`UIRequest::PinDialog` 或 `UIRequest::AuthDialog`），bridge 线程用 `slint::invoke_from_event_loop` 调度到主线程，结果通过 `oneshot` channel 返回。
- **移除 UV 路径用于自动解锁:** UV 仅验证身份不恢复密钥，vault.enc 启动后 `cached_key_tuples` 为空。`prompt_windows_hello()` 保留供 CLI 纯身份验证。
- **签名路径优先:** 自动解锁优先签名路径（无需交互），失败后降级到 PIN 对话框（需用户输入）。
- **Focus helper:** 签名路径使用后台线程持续调用 focus helper，确保安全提示窗口前置。
- **spawn_blocking:** WinRT 同步 API 不能在 tokio 异步运行时中直接调用。
