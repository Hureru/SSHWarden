# Architecture of IPC Control Channel

## 1. Identity

- **What it is:** SSHWarden 守护进程与 CLI 子命令之间的进程间通信通道，基于 Windows Named Pipe 和 JSON 协议。
- **Purpose:** 允许用户通过 `sshwarden lock/unlock/unlock --hello/unlock --pin/unlock --password/status/sync/set-pin` 等 CLI 命令远程控制正在运行的守护进程。

## 2. Core Components

- `crates/sshwarden-agent/src/control.rs` (`ControlCommand`, `ControlResponse`, `ControlRequest`, `ControlAction`, `start_control_server`, `send_control_command`): IPC 控制通道的完整实现——服务端（守护进程）和客户端（CLI）。
- `crates/sshwarden-agent/src/lib.rs`: 导出 `ControlAction`, `ControlRequest`, `ControlResponse`, `CONTROL_PIPE_NAME`。
- `src/main.rs` (`handle_control_command`): 主循环中处理 `ControlAction` 的业务逻辑。参见 `src/main.rs:508-943`.

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 服务端（守护进程）

- **1. 启动:** `run_foreground()` 创建 `mpsc::channel<ControlRequest>(16)` 并 spawn `start_control_server(tx, cancel_token)`. 参见 `src/main.rs:412-420`.
- **2. 监听:** `start_control_server()` 循环创建 Named Pipe 实例 (`\\.\pipe\sshwarden-control`)，通过 `tokio::select!` 等待连接或取消. 参见 `crates/sshwarden-agent/src/control.rs:91-128`.
- **3. 读取命令:** 从客户端读取一行 JSON (`ControlCommand`)，解析 `cmd` 字段匹配 action. 参见 `crates/sshwarden-agent/src/control.rs:148-188`.
- **4. 命令解析:** 支持 8 种命令字符串到 `ControlAction` 枚举的映射: `lock`, `unlock`, `unlock-hello`, `status`, `sync`, `unlock-pin:{pin}`, `unlock-password:{password}`, `set-pin:{pin}`. 参见 `crates/sshwarden-agent/src/control.rs:161-188`.
- **5. 转发请求:** 构建 `ControlRequest`（含 `ControlAction` + `oneshot::Sender`），通过 `tx.send()` 发给主循环. 参见 `crates/sshwarden-agent/src/control.rs:191-205`.
- **6. 等待响应:** 在 `reply_rx.await` 上等待主循环处理结果. 参见 `crates/sshwarden-agent/src/control.rs:207-210`.
- **7. 回写:** 将 `ControlResponse` 序列化为 JSON 写回客户端. 参见 `crates/sshwarden-agent/src/control.rs:212-216`.

### 3.2 客户端（CLI 子命令）

- **1. 连接:** `send_control_command()` 通过 `ClientOptions::new().open(CONTROL_PIPE_NAME)` 连接到守护进程. 参见 `crates/sshwarden-agent/src/control.rs:222-232`.
- **2. 发送:** 序列化 `ControlCommand` 为 JSON 并写入 pipe. 参见 `crates/sshwarden-agent/src/control.rs:237-241`.
- **3. 接收:** 读取一行 JSON 反序列化为 `ControlResponse`. 参见 `crates/sshwarden-agent/src/control.rs:246-249`.

### 3.3 ControlAction 枚举

参见 `crates/sshwarden-agent/src/control.rs:67-76`:

| Variant | 字段 | 描述 |
|---|---|---|
| `Lock` | - | 锁定密码库 |
| `Unlock` | - | 自动解锁（先尝试 Hello 签名路径，再降级 UV） |
| `UnlockHello` | - | 仅 Hello 签名路径解锁 |
| `UnlockPin` | `pin: String` | PIN 解密解锁 |
| `UnlockPassword` | `password: String` | 主密码重新登录解锁 |
| `Status` | - | 查询状态 |
| `Sync` | - | 重新同步密码库 |
| `SetPin` | `pin: String` | 设置 PIN |

## 4. Design Rationale

- **Named Pipe 单连接模型:** 每个客户端连接处理一条命令即关闭，简化并发和状态管理。
- **oneshot 回复通道:** 每个请求附带独立的 `oneshot::Sender`，避免响应混淆。
- **CancellationToken:** 守护进程关闭时通过 token 取消 control server 的等待循环。
- **first_pipe_instance fallback:** 首次创建 pipe 尝试 `first_pipe_instance(false)`，失败后尝试 `first_pipe_instance(true)`，处理首次启动和已有实例两种情况。
