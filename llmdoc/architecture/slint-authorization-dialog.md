# Architecture of Slint Authorization Dialog

## 1. Identity

- **What it is:** 跨平台的 SSH 签名请求授权对话框，使用 Slint GUI 框架实现，替代原有的 Windows-only Toast 通知 + TaskDialog/MessageBox。
- **Purpose:** 在 SSH 签名请求到达时，向用户展示进程名、密钥名、操作类型和代理转发警告，通过 Approve/Deny 按钮获取用户授权决策。

## 2. Core Components

- `crates/sshwarden-ui/src/lib.rs` (`SignRequestInfo`, `AuthorizationResult`, `UIRequest`): 签名请求信息结构体、授权结果枚举（Approved/Denied/Timeout）、统一 UI 请求枚举（`UIRequest::AuthDialog` 变体）.
- `crates/sshwarden-ui/src/notify/mod.rs`: 导出 `show_auth_dialog`、`request_authorization`、`AuthDialogRequest`.
- `crates/sshwarden-ui/src/notify/slint_dialog.rs` (`AuthDialogRequest`, `show_auth_dialog`, `request_authorization`, `center_and_focus_dialog`): Slint 授权对话框核心实现。`slint::slint!{}` 内联宏定义 `AuthDialog` 窗口组件，`show_auth_dialog()` 在 Slint 主线程创建对话框，`request_authorization()` 从 tokio 线程异步请求，`center_and_focus_dialog()` 跨平台居中+聚焦（slint_center_win + winit focus_window）.
- `src/main.rs` (`run_slint_event_loop`): bridge 线程 match `UIRequest::AuthDialog` 分支，构造 `AuthDialogRequest` 后通过 `slint::invoke_from_event_loop` 调度 `show_auth_dialog()`.

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 授权对话框调用（3 处调用点）

- **1a. Hello 签名路径解锁后:** 自动解锁成功后，若 `prompt_behavior` 要求授权，调用 `request_authorization()`. 参见 `src/main.rs:1425-1448`.
- **1b. PIN 对话框解锁后:** PIN 解锁成功后，检查 `prompt_behavior`，需要时调用 `request_authorization()`. 参见 `src/main.rs:1509-1532`.
- **1c. 正常签名请求:** vault 未锁定时的常规签名，直接调用 `request_authorization()`. 参见 `src/main.rs:1596`.

### 3.2 跨线程调度流程

- **2. 构建 UIRequest:** `request_authorization()` 创建 `oneshot` channel，封装 `UIRequest::AuthDialog { info, response_tx }` 发送到 `mpsc` 通道. 参见 `crates/sshwarden-ui/src/notify/slint_dialog.rs:189-214`.
- **3. Bridge 线程接收:** bridge 线程从 mpsc 接收 `UIRequest::AuthDialog`，构造 `AuthDialogRequest`，调用 `slint::invoke_from_event_loop`. 参见 `src/main.rs:269-284`.
- **4. Slint 主线程创建对话框:** `show_auth_dialog()` 创建 `AuthDialog` 窗口，设置进程名、密钥名、操作类型、代理转发标志. 参见 `crates/sshwarden-ui/src/notify/slint_dialog.rs:125-144`.
- **5. 用户交互:** Approve 按钮 -> `AuthorizationResult::Approved`，Deny 按钮/关闭窗口 -> `AuthorizationResult::Denied`. 结果通过 `oneshot` channel 返回. 参见 `crates/sshwarden-ui/src/notify/slint_dialog.rs:148-179`.
- **6. 结果返回:** `request_authorization()` await oneshot 结果，返回 `AuthorizationResult`. channel 关闭则默认 `Denied`.

### 3.3 窗口居中与聚焦

- **`center_and_focus_dialog()`:** 跨平台函数（无 `#[cfg]` 条件编译），先调用 `slint_center_win::center_window()` 居中窗口，再通过 `slint::winit_030::WinitWindowAccessor::with_winit_window()` 获取底层 winit 窗口并调用 `focus_window()` 确保窗口前置激活. 参见 `crates/sshwarden-ui/src/notify/slint_dialog.rs:134-142`.
- **延迟调度:** `dialog.show()` 成功后，通过 `Timer::single_shot(30ms)` 延迟执行居中+聚焦（确保窗口尺寸就绪后再居中）. 参见 `crates/sshwarden-ui/src/notify/slint_dialog.rs:204-210`.
- **依赖:** Slint 需启用 `unstable-winit-030` feature 以暴露 `WinitWindowAccessor` API. 参见 `crates/sshwarden-ui/Cargo.toml:13`.

### 3.4 AuthDialog UI 组件

- **窗口属性:** 380x195px, always-on-top, 系统 Palette 配色（跟随暗色/亮色主题），`default-font-family: "Segoe UI"`.
- **显示内容:** 进程名（22px 粗体）、"is requesting to use an SSH key"（13px）、Key 名（13px）、Operation（13px，Git Signing/SSH Authentication/自定义 namespace）.
- **代理转发警告:** `is-forwarding` 为 true 时显示橙色警告条.
- **布局:** 内边距 16px，间距 8px，按钮高度显式 30px.
- **按钮:** Deny（普通）+ Approve（primary），右对齐.
- 参见 `crates/sshwarden-ui/src/notify/slint_dialog.rs:3-127`.

## 4. Design Rationale

- **Slint 替代 Toast 通知:** 原方案使用 Windows WinRT ToastNotification（需 AUMID、PowerShell fallback）+ TaskDialog + MessageBox fallback，仅 Windows 可用。Slint 实现跨平台（Windows/Linux/macOS），无平台依赖。
- **移除条件编译:** 不再有 `notify/windows.rs`（Toast+TaskDialog）和 `notify/fallback.rs`（non-Windows 自动批准），所有平台使用统一的 Slint 授权对话框。
- **复用 UIRequest 通道:** 授权对话框复用与 PIN 对话框相同的 `mpsc::channel<UIRequest>` + bridge 线程 + `slint::invoke_from_event_loop` 架构，无需额外的 `spawn_blocking`。
- **Rc<RefCell<Option<Sender>>>:** AuthDialog 多个回调（approve/deny/close）共享 oneshot sender 的标准模式，确保只发送一次结果。注意 PinDialog 已改为 `Arc<Mutex>` 以支持跨线程 validator（参见 `/llmdoc/architecture/sshwarden-windows-hello-unlock.md`）。
- **跨平台窗口居中+聚焦:** `center_and_focus_dialog()` 移除了原先的 `#[cfg(windows)]`/`#[cfg(not(windows))]` 条件编译分支，改为统一的跨平台实现。通过 Slint `unstable-winit-030` feature 暴露 `WinitWindowAccessor` API，获取底层 winit 窗口调用 `focus_window()` 确保前置激活。配合 `slint_center_win::center_window()` 实现居中。
- **UI 美化:** AuthDialog 调整为紧凑布局（380x195px、16px 内边距、8px 间距），设置 `default-font-family: "Segoe UI"` 解决 Windows 字体问题，进程名 22px 加粗突出显示，正文统一 13px，按钮高度显式 30px。
