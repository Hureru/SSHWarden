# Architecture of Windows Toast Notification Authorization

## 1. Identity

- **What it is:** Windows 平台上的 SSH 签名请求授权通知系统，使用 WinRT ToastNotification API 显示交互式通知。
- **Purpose:** 在 SSH 签名请求到达时，向用户展示密钥名、请求进程、操作类型，并通过 [授权]/[拒绝] 按钮获取用户决策。

## 2. Core Components

- `crates/sshwarden-ui/src/lib.rs` (`SignRequestInfo`, `AuthorizationResult`): 签名请求信息结构体和授权结果枚举（Approved/Denied/Timeout）。
- `crates/sshwarden-ui/src/notify/mod.rs`: 条件编译分派，Windows 使用 `windows.rs`，其他平台使用 `fallback.rs`。
- `crates/sshwarden-ui/src/notify/windows.rs` (`prompt_authorization`, `show_toast`, `show_message_box_fallback`): Toast 通知核心实现，包含 fallback 到 Win32 MessageBox。

## 3. Execution Flow (LLM Retrieval Map)

- **1. 调用入口:** `src/main.rs` 中的 `handle_ui_request()` 构建 `SignRequestInfo` 后调用 `sshwarden_ui::notify::prompt_authorization(&sign_info)`. 参见 `src/main.rs:701-716`.
- **2. spawn_blocking:** `prompt_authorization()` 通过 `tokio::task::spawn_blocking` 在独立线程调用 `show_toast()`. 参见 `crates/sshwarden-ui/src/notify/windows.rs:25`.
- **3. 构建 Toast XML:** `show_toast()` 构建 `scenario="urgent"` 的 Toast XML，包含密钥名、进程名、操作类型（Git 签名/SSH 认证）和代理转发警告。参见 `crates/sshwarden-ui/src/notify/windows.rs:55-74`.
- **4. 注册事件回调:** 注册三个 `TypedEventHandler` 闭包：Activated（按钮点击）、Dismissed（关闭/超时）、Failed（失败）。闭包参数是 `Ref<'_, T>` 类型，deref 到 `Option<T>`，需通过 `Interface` trait 的 `cast()` 方法转换为 `ToastActivatedEventArgs`。参见 `crates/sshwarden-ui/src/notify/windows.rs:85-122`.
- **5. 显示通知:** 通过 `ToastNotificationManager::CreateToastNotifierWithId` 使用 PowerShell AUMID 作为通知源，调用 `notifier.Show()`. 参见 `crates/sshwarden-ui/src/notify/windows.rs:125-127`.
- **6. 等待响应:** `mpsc::channel` 接收回调结果，60 秒 `recv_timeout`。超时返回 `AuthorizationResult::Timeout` 并隐藏通知。参见 `crates/sshwarden-ui/src/notify/windows.rs:130-140`.
- **7. Fallback:** 若 Toast 失败，`show_message_box_fallback()` 使用 Win32 `MessageBoxW` (YES/NO) 作为备选。参见 `crates/sshwarden-ui/src/notify/windows.rs:143-183`.

## 4. Design Rationale

- **PowerShell AUMID:** 未注册自有 AUMID 时，复用 PowerShell 的 AUMID (`{1AC14E77-...}\\powershell.exe`) 作为 fallback，确保在任何 Windows 10+ 系统上都能显示 Toast 通知。
- **scenario="urgent":** 使 Toast 在操作中心顶部显示且不自动消失，确保用户注意到安全敏感请求。
- **TypedEventHandler 闭包:** WinRT 回调参数是 `Ref<'_, T>`（解引用为 `Option<T>`），不能直接使用——需先解引用获取 `Option<IInspectable>`，再用 `Interface::cast()` 转换为具体事件参数类型。
- **MessageBox fallback:** Toast 在某些环境（如 RDP、无桌面服务）可能失败，MessageBox 作为最低保障的 UI 手段。
