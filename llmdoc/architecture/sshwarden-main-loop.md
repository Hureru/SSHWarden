# Architecture of SSHWarden Main Loop

## 1. Identity

- **What it is:** SSHWarden 守护进程的异步主循环，使用 `tokio::select!` 统一处理四类事件。
- **Purpose:** 协调 IPC 控制命令、SSH Agent UI 请求、自动锁定检查和关闭信号，确保守护进程的所有功能在单一循环中有序运行。

## 2. Core Components

- `src/main.rs` (`run_foreground`): 主循环入口，初始化所有通道和共享状态后进入 `tokio::select!` 循环. 参见 `src/main.rs:323-504`.
- `src/main.rs` (`handle_control_command`): 处理 8 种 IPC 控制命令（Lock, Unlock, UnlockHello, UnlockPin, UnlockPassword, Status, Sync, SetPin）. 参见 `src/main.rs:508-943`.
- `src/main.rs` (`handle_ui_request`): 处理 SSH Agent 的 UI 请求（列表/签名），含三级自动解锁，每个请求 spawn 独立 task. 参见 `src/main.rs:995-1150`.
- `src/main.rs` (`finish_unlock_with_json`): 共用的解锁完成逻辑（JSON 解析 -> key_names 更新 -> Agent 加载 -> 锁定标志清除）. 参见 `src/main.rs:956-991`.
- `src/main.rs` (`try_hello_unlock`): Windows Hello 签名路径解锁辅助函数. 参见 `src/main.rs:948-953`.

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 启动初始化

- **1. vault.enc 检测:** `VaultFile::load()` 检查 exe 同目录下的持久化文件是否存在。若存在，跳过主密码提示，设置初始锁定状态. 参见 `src/main.rs:328-334`.
- **2. 条件登录:** 若无 vault.enc 且有 email 配置，`fetch_vault_keys_with_client()` 提示输入主密码并通过 Bitwarden API 登录同步密钥；若有 vault.enc 则跳过. 参见 `src/main.rs:338-357`.
- **3. 创建通道:** `request_tx/rx` (mpsc, SSH UI 请求), `response_tx/rx` (broadcast, 审批响应). 参见 `src/main.rs:360-364`.
- **4. 启动 Agent:** `SshWardenAgent::start_server()` 启动 Named Pipe/Unix Socket 监听. 参见 `src/main.rs:367-368`.
- **5. 共享状态:** `cached_key_tuples`, `vault_locked`, `api_client`, `pin_encrypted_keys`, `vault_file_data`, `key_names` 通过 `Arc<RwLock<>>` / `Arc<AtomicBool>` 共享. 参见 `src/main.rs:383-393`.
- **6. 启动 control server:** spawn `start_control_server()` 监听 `\\.\pipe\sshwarden-control`. 参见 `src/main.rs:417-420`.

### 3.2 tokio::select! 四路事件处理

参见 `src/main.rs:432-498`:

- **control_rx.recv():** 接收 IPC 控制命令，调用 `handle_control_command()` 后回复. 更新 `last_activity` 时间戳. 新增 UnlockHello 和 UnlockPassword 命令支持.
- **request_rx.recv():** 接收 SSH Agent UI 请求，spawn 独立 task 调用 `handle_ui_request()`. 新增签名路径自动解锁. 更新 `last_activity` 时间戳.
- **lock_check_interval.tick():** 每 60 秒检查自动锁定——若 `lock_timeout > 0` 且自上次活动已超过 `lock_timeout` 秒，执行 `agent.lock()` 并设置 `vault_locked = true`.
- **ctrl_c:** 收到 Ctrl+C 后 break 退出主循环.

### 3.3 关闭流程

- **1. break:** 退出 select! 循环.
- **2. cancel:** `cancel_token.cancel()` 通知 control server 停止.
- **3. stop agent:** `agent.stop()` 清除密钥并取消 SSH 监听. 参见 `src/main.rs:500-503`.

## 4. Design Rationale

- **单循环多路复用:** 所有事件在同一 `tokio::select!` 中处理，避免多个独立循环的同步复杂度。
- **spawn per request:** UI 请求 spawn 独立 task，因为 Windows Hello 和 Toast 通知可能阻塞数十秒。
- **vault.enc 启动分支:** 有 vault.enc 时跳过密码提示进入锁定态，减少交互需求，特别适合 daemon 模式自动启动场景。
- **启动文件夹自启动:** `daemon --install` 使用用户启动文件夹快捷方式（而非 Task Scheduler），确保守护进程在用户交互式桌面会话中运行，Toast 通知和 Windows Hello 等 UI 交互正常工作。参见 `src/main.rs:1458-1535`.
- **last_activity 跟踪:** IPC 命令和 SSH 请求都更新活动时间戳，防止在活跃使用期间触发自动锁定。
- **lock_timeout 可配置:** `agent.lock_timeout` 默认 3600 秒，设为 0 禁用自动锁定。
