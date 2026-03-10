# Architecture of Windows Hello Unlock in SSHWarden

## 1. Identity

- **What it is:** SSHWarden 的 Windows Hello 解锁模块，提供签名路径（KeyCredentialManager 持久化密钥派生）和 Slint PIN 对话框降级路径（跨平台）。
- **Purpose:** 在密码库锁定时，通过 Windows Hello（指纹/面部/PIN）验证用户身份并恢复 SSH 密钥。签名路径支持跨守护进程重启的持久化解锁。Hello 不可用时，通过 Slint 跨平台 PIN 对话框降级。

## 2. Core Components

- `crates/sshwarden-ui/src/unlock/mod.rs` (`UnlockResult`, `show_pin_dialog`, `request_pin_dialog`): 解锁结果枚举，导出 Slint PIN 对话框的跨线程通信函数.
- `crates/sshwarden-ui/src/unlock/slint_dialog.rs` (`show_pin_dialog`, `request_pin_dialog`, `center_and_focus_dialog`, `trigger_shake`): Slint PIN 对话框实现——`slint::slint!{}` 内联宏定义暗色主题窗口。对话框在验证通过前保持打开：`validator` 闭包在 `std::thread::spawn` 后台线程中执行，成功则发送结果并关闭，失败则清空输入、显示红色错误提示并触发抖动动画。`tx_cell` 使用 `Arc<Mutex>` 以支持跨线程到 `invoke_from_event_loop` 回调。`trigger_shake()` 复用抖动动画逻辑。
- `crates/sshwarden-ui/src/unlock/windows.rs` (`prompt_windows_hello`, `focus_and_center_security_prompt_pub`): Windows Hello UV 路径（仅 CLI `unlock` 使用）+ 窗口居中辅助.
- `crates/sshwarden-ui/src/unlock/hello_crypto.rs` (`hello_derive_key`, `hello_encrypt_keys`, `hello_decrypt_keys`, `hello_available`, `credential_set`, `credential_get`, `credential_delete`, `credential_exists`): Windows Hello 签名路径 + Windows Credential Manager 加密缓存.
- `src/main.rs` (`handle_ui_request`, `handle_control_command`, `try_hello_unlock`, `finish_unlock_with_json`, `run_slint_event_loop`, `get_pin_encrypted_data`, `make_pin_validator`): 调用入口、解锁逻辑和 Slint 事件循环。`get_pin_encrypted_data()` 统一读取 PIN 加密数据（优先内存、降级 vault.enc）。`make_pin_validator()` 构造 validator 闭包并通过 `Arc<Mutex<Option<String>>>` 缓存解密结果，避免验证成功后再次执行 Argon2id KDF。

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 签名路径解锁 (KeyCredentialManager)

- **1. 触发:** CLI `unlock --hello` 或 `unlock` 自动优先尝试签名路径，或 SSH 请求触发自动解锁. 参见 `src/main.rs:710-750` (Unlock), `src/main.rs:801-878` (UnlockHello), `src/main.rs:1350-1448` (handle_ui_request sign).
- **2. 读取 challenge:** 从 `vault_file_data` 读取 `hello_challenge` 和 `hello_encrypted`.
- **3. spawn_blocking:** `try_hello_unlock(challenge, hello_encrypted)` 在阻塞线程池执行.
- **4. Hello 密钥派生:** `hello_derive_key(challenge)` 签名 challenge，SHA-256 得到 enc_key. 参见 `crates/sshwarden-ui/src/unlock/hello_crypto.rs:33-90`.
- **5. AES 解密:** `hello_decrypt_keys()` 解密 EncString 得到密钥 JSON. 参见 `crates/sshwarden-ui/src/unlock/hello_crypto.rs:230-246`.
- **6. 完成解锁:** `finish_unlock_with_json()` 解析 JSON、加载到 Agent、清除锁定标志. 参见 `src/main.rs:1170-1204`.

### 3.2 Slint PIN 对话框降级路径（含 validator 重试模式）

- **1. 触发:** Hello 签名路径失败后，在三个位置降级：ControlAction::Unlock (`src/main.rs:758-787`)、list 请求 (`src/main.rs:1316-1340`)、sign 请求 (`src/main.rs:1460-1500`).
- **2. 读取加密数据:** 调用 `get_pin_encrypted_data()` 优先从内存 `pin_encrypted_keys` 读取，若为空则从 `vault_file_data` 读取. 参见 `src/main.rs:1162-1174`.
- **3. 构造 validator:** 调用 `make_pin_validator(enc_data)` 构造 validator 闭包和 `decrypted_cache`（`Arc<Mutex<Option<String>>>`）。闭包内部调用 `pin_decrypt()` 验证 PIN，成功时将解密结果缓存. 参见 `src/main.rs:1180-1202`.
- **4. 异步请求:** 调用 `request_pin_dialog(&ui_request_tx, validator)` 向 Slint 主线程发送 `UIRequest::PinDialog { response_tx, validator }`，通过 oneshot channel 等待结果. 参见 `crates/sshwarden-ui/src/unlock/slint_dialog.rs:237-266`.
- **5. Slint 调度:** bridge 线程接收 `UIRequest::PinDialog`，解构出 `response_tx` 和 `validator`，`slint::invoke_from_event_loop` 调用 `show_pin_dialog(response_tx, validator)` 在主线程创建 Slint 窗口. 参见 `src/main.rs:248-258`.
- **6. 用户交互与验证循环:** 用户输入 PIN 后触发 `try-submit()`。若 `verifying` 为 true 则防重复提交。PIN 非空时 `on_submit_pin` 回调设置 `verifying=true`（禁用输入和按钮，按钮文本变为 "Verifying..."），`std::thread::spawn` 后台线程调用 `validator(&pin)`。通过 `invoke_from_event_loop` 回到 Slint 主线程：成功则发送结果并关闭对话框，失败则清空输入、显示 "Incorrect PIN, please try again" 红色提示、触发抖动动画、恢复 `verifying=false` 允许重试. 参见 `crates/sshwarden-ui/src/unlock/slint_dialog.rs:154-190`.
- **7. 取回解密结果:** `request_pin_dialog()` 返回 `Some(pin)` 后，调用方从 `decrypted_cache.lock().unwrap().take().unwrap()` 取回已缓存的解密 JSON，避免再次执行 Argon2id KDF. 参见 `src/main.rs:771-772`.
- **8. 授权对话框:** PIN 解锁成功后，若 `prompt_behavior` 要求授权，调用 `request_authorization()` 弹出 Slint 授权对话框.
- **9. 完成解锁:** 调用 `finish_unlock_with_json()` 加载密钥.

### 3.3 SSH 请求自动解锁优先级

- **1. Hello 签名路径:** 检查 vault_file_data 中的 hello_challenge，尝试 `try_hello_unlock()`.
- **2. Slint PIN 对话框降级:** 签名路径失败后，`request_pin_dialog()` 弹出 Slint PIN 对话框.
- **3. 拒绝:** 两者均失败则拒绝当前 SSH 请求.

## 4. Design Rationale

- **Slint 替代 Win32 PIN 对话框:** 使用 Slint GUI 框架（`slint::slint!{}` 内联宏）替代 ~460 行 Win32 原生 API 代码（Acrylic/DPI/字体/消息循环），实现跨平台 Windows/Linux/macOS 支持。
- **Validator 闭包注入:** PIN 验证逻辑从调用方移入对话框内部，通过 `validator: Arc<dyn Fn(&str) -> bool + Send + Sync>` 闭包注入。对话框不再是一次性的（submit-then-close），而是在验证失败时保持打开、显示错误提示并允许重试。验证在 `std::thread::spawn` 后台线程执行，避免 Argon2id KDF 阻塞 Slint 主线程。
- **decrypted_cache 避免重复 KDF:** `make_pin_validator()` 通过 `Arc<Mutex<Option<String>>>` 在 validator 闭包成功时缓存解密结果，调用方直接从 cache 取回 JSON，无需再次执行 Argon2id 派生+AES 解密。
- **Arc<Mutex> 替代 Rc<RefCell>:** `tx_cell`（oneshot sender 的共享容器）从 `Rc<RefCell>` 改为 `Arc<Mutex>`，因为 `on_submit_pin` 回调中 `std::thread::spawn` 后需要在 `invoke_from_event_loop` 闭包中访问 sender，跨线程要求 `Send`。
- **跨线程通信机制:** Slint 要求主线程运行事件循环。tokio 线程通过 `mpsc::channel<UIRequest>` 发送请求（`UIRequest::PinDialog` 或 `UIRequest::AuthDialog`），bridge 线程用 `slint::invoke_from_event_loop` 调度到主线程，结果通过 `oneshot` channel 返回。
- **移除 UV 路径用于自动解锁:** UV 仅验证身份不恢复密钥，vault.enc 启动后 `cached_key_tuples` 为空。`prompt_windows_hello()` 保留供 CLI 纯身份验证。
- **签名路径优先:** 自动解锁优先签名路径（无需交互），失败后降级到 PIN 对话框（需用户输入）。
- **Focus helper:** 签名路径使用后台线程持续调用 focus helper，确保安全提示窗口前置。
- **spawn_blocking:** WinRT 同步 API 不能在 tokio 异步运行时中直接调用。
- **跨平台窗口居中+聚焦:** `center_and_focus_dialog()` 移除了 `#[cfg(windows)]` 条件编译，通过 Slint `unstable-winit-030` feature 暴露的 `WinitWindowAccessor` 获取底层 winit 窗口并调用 `focus_window()`，在所有 winit 支持的平台工作。
