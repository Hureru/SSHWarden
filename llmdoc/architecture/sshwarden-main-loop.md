# Architecture of SSHWarden Main Loop

## 1. Identity

- **What it is:** SSHWarden 守护进程的双线程架构：主线程运行 Slint GUI 事件循环，tokio 运行时在独立线程处理异步主循环（`tokio::select!` 四路事件）。
- **Purpose:** 协调 IPC 控制命令、SSH Agent UI 请求、自动锁定检查和关闭信号。Slint 事件循环在主线程确保 PIN 对话框和授权对话框等 GUI 组件正常工作。

## 2. Core Components

- `src/main.rs` (`main`): 同步入口，判断是否需要 UI。需要时创建 `mpsc::channel<UIRequest>`，在独立线程启动 tokio 运行时，主线程运行 `run_slint_event_loop()`. 参见 `src/main.rs:80-237`.
- `src/main.rs` (`run_slint_event_loop`): 主线程 Slint 事件循环，bridge 线程从 mpsc 接收 `UIRequest`，match 分发到 `show_pin_dialog()` 或 `show_auth_dialog()`. 参见 `src/main.rs:243-290`.
- `src/main.rs` (`run_foreground`): tokio 线程中的异步主循环入口，初始化通道和共享状态后进入 `tokio::select!` 循环. 参见 `src/main.rs:436-668`.
- `src/main.rs` (`handle_control_command`): 处理 8 种 IPC 控制命令，PIN 对话框降级通过 `request_pin_dialog()` 异步请求 Slint 主线程. 参见 `src/main.rs:672-1160`.
- `src/main.rs` (`handle_ui_request`): 处理 SSH Agent UI 请求（列表/签名），含二级自动解锁（Hello 签名路径 -> Slint PIN 对话框）和 Slint 授权对话框. 参见 `src/main.rs:1209-1599`.
- `src/main.rs` (`finish_unlock_with_json`): 共用的解锁完成逻辑（JSON 解析 -> key_names 更新 -> Agent 加载 -> 锁定标志清除）. 参见 `src/main.rs:1170-1204`.
- `src/main.rs` (`try_hello_unlock`): Windows Hello 签名路径解锁辅助函数. 参见 `src/main.rs:1165-1167`.
- `crates/sshwarden-ui/src/lib.rs` (`UIRequest`): 统一的跨线程 UI 请求枚举，包含 `PinDialog` 和 `AuthDialog` 两种变体.
- `crates/sshwarden-ui/src/unlock/slint_dialog.rs` (`show_pin_dialog`, `request_pin_dialog`): Slint PIN 对话框实现及跨线程通信机制.
- `crates/sshwarden-ui/src/notify/slint_dialog.rs` (`AuthDialogRequest`, `show_auth_dialog`, `request_authorization`): Slint 授权对话框实现及跨线程通信机制.

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 双线程启动

- **1. main() 入口:** 同步 `fn main()` 初始化 DPI、解析 CLI、配置日志. 参见 `src/main.rs:80-131`.
- **2. 判断 UI 需求:** 前台/daemon 模式需要 Slint UI (`needs_ui = true`). 参见 `src/main.rs:124-130`.
- **3. 创建 UI 通道:** `mpsc::channel<UIRequest>(1)` 用于 tokio <-> Slint 跨线程通信，统一 PIN 对话框和授权对话框请求. 参见 `src/main.rs:134-136`.
- **4. 启动 tokio 线程:** `std::thread::spawn` 中 `rt.block_on(run_foreground(config, ui_tx))`. 参见 `src/main.rs:147-166`.
- **5. 主线程 Slint 循环:** `run_slint_event_loop(ui_request_rx)` 阻塞直到 `slint::quit_event_loop()`. 参见 `src/main.rs:169`.
- **6. Bridge 线程:** 在 Slint 循环内 spawn 桥接线程，接收 `UIRequest`，match 分发：`PinDialog` -> `show_pin_dialog()`，`AuthDialog` -> `show_auth_dialog()`，均通过 `slint::invoke_from_event_loop` 调度到主线程. 参见 `src/main.rs:247-289`.

### 3.2 异步主循环初始化（tokio 线程内）

- **1. vault.enc 检测:** `VaultFile::load()` 检查 exe 同目录持久化文件，存在则跳过主密码提示. 参见 `src/main.rs:444-449`.
- **2. 条件登录:** 无 vault.enc 且有 email 配置时 `fetch_vault_keys_with_client()` 登录同步. 参见 `src/main.rs:455-500`.
- **3. 创建通道:** `request_tx/rx` (mpsc), `response_tx/rx` (broadcast). 参见 `src/main.rs:503-506`.
- **4. 启动 Agent:** `SshWardenAgent::start_server()`. 参见 `src/main.rs:509-510`.
- **5. 共享状态:** `cached_key_tuples`, `vault_locked`, `pin_encrypted_keys`, `vault_file_data` 等. 参见 `src/main.rs:525-534`.
- **6. 启动 control server:** spawn `start_control_server()`. 参见 `src/main.rs:575-581`.

### 3.3 tokio::select! 四路事件处理

参见 `src/main.rs:593-662`:

- **control_rx.recv():** IPC 控制命令，`handle_control_command()` 接收 `ui_request_tx` 用于 PIN 对话框降级. 更新 `last_activity`.
- **request_rx.recv():** SSH Agent UI 请求，spawn 独立 task，传入 `ui_request_tx` 克隆. 自动解锁：Hello 签名 -> Slint PIN 对话框. 授权：Slint 授权对话框（替代原 Toast 通知）.
- **lock_check_interval.tick():** 每 60 秒检查自动锁定.
- **ctrl_c:** break 退出.

### 3.4 关闭流程

- **1. break:** 退出 select! 循环. tokio 线程结束.
- **2. cancel:** `cancel_token.cancel()` 通知 control server. 参见 `src/main.rs:664`.
- **3. stop agent:** `agent.stop()`. 参见 `src/main.rs:665`.
- **4. channel 关闭:** `ui_request_tx` drop 后 bridge 线程检测到关闭，调用 `slint::quit_event_loop()` 退出主线程. 参见 `src/main.rs:288`.

## 4. Design Rationale

- **双线程模型:** Slint 要求 GUI 事件循环在主线程运行。tokio 异步运行时移至独立线程，通过 `mpsc` 通道和 `slint::invoke_from_event_loop` 桥接跨线程 UI 请求（PIN 对话框 + 授权对话框）。
- **UIRequest 统一枚举:** `UIRequest` 枚举统一了 `PinDialog` 和 `AuthDialog` 两种跨线程 UI 请求，替代了之前独立的 `PinDialogRequest` 类型。bridge 线程 match 分发到不同的 Slint 对话框。
- **Bridge 线程:** 使用独立的 `current_thread` tokio 运行时从 mpsc 接收请求，避免在 Slint 主线程上阻塞等待。
- **spawn per request:** UI 请求 spawn 独立 task，因为 Windows Hello、PIN 对话框和 Toast 通知可能阻塞数十秒。
- **vault.enc 启动分支:** 有 vault.enc 时跳过密码提示进入锁定态，适合 daemon 自启动。
- **启动文件夹自启动:** `daemon --install` 使用用户启动文件夹快捷方式. 参见 `src/main.rs:1792-1836`.
- **last_activity 跟踪:** IPC 命令和 SSH 请求都更新活动时间戳.
- **lock_timeout 可配置:** 默认 3600 秒，设为 0 禁用。
