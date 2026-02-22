# SSH Agent 多平台实现架构

## 1. Identity

- **What it is:** SSH Agent 服务端的平台特定实现层，通过条件编译为 Windows、macOS 和 Linux 提供各自的 IPC 监听和对等进程识别机制。
- **Purpose:** 在不同操作系统上以平台原生方式暴露 SSH Agent 服务（Windows Named Pipe / Unix Domain Socket），同时统一上层协议处理接口。

## 2. Core Components

- `desktop/desktop_native/core/src/ssh_agent/mod.rs` (`BitwardenDesktopAgent`, `platform_ssh_agent`): 中枢模块。通过 `#[cfg_attr]`（第 18-21 行）将 `platform_ssh_agent` 模块分派到 `windows.rs` 或 `unix.rs`。
- `desktop/desktop_native/core/src/ssh_agent/windows.rs` (`start_server`): Windows 实现入口。创建 `NamedPipeServerStream` 并启动 tokio 任务运行 `ssh_agent::serve()`。
- `desktop/desktop_native/core/src/ssh_agent/named_pipe_listener_stream.rs` (`NamedPipeServerStream`, `PIPE_NAME`): Windows Named Pipe 监听器。硬编码管道路径 `\\.\pipe\openssh-ssh-agent`，使用 Win32 `GetNamedPipeClientProcessId` 获取客户端 PID。通过 mpsc channel 桥接到 `futures::Stream`。
- `desktop/desktop_native/core/src/ssh_agent/unix.rs` (`start_server`, `get_socket_path`, `get_default_socket_path`, `is_flatpak`, `set_user_permissions`, `remove_path`): Unix 实现入口（macOS 和 Linux 共用）。Socket 路径可配置，支持 Flatpak 环境，设置 `0o600` 权限。
- `desktop/desktop_native/core/src/ssh_agent/peercred_unix_listener_stream.rs` (`PeercredUnixListenerStream`): Unix Domain Socket 流包装器。调用 `peer_cred()` 获取 PID，失败时回退到 `PeerInfo::unknown()`。
- `desktop/desktop_native/core/src/ssh_agent/peerinfo/gather.rs` (`get_peer_info`): 跨平台进程信息解析。使用 `sysinfo` crate 将 PID 解析为进程名称。
- `desktop/desktop_native/core/src/ssh_agent/peerinfo/models.rs` (`PeerInfo`): 对等进程信息模型。包含 `uid`、`pid`、`process_name` 及可变的 `is_forwarding`/`host_key` 字段。

## 3. Execution Flow (LLM Retrieval Map)

### Windows 流程

- **1. 条件编译:** `mod.rs:18` 选择 `windows.rs` 作为 `platform_ssh_agent` 模块。
- **2. 启动服务:** `windows.rs:11-39` 的 `start_server()` 创建 `NamedPipeServerStream`，传入 `CancellationToken` 和 `is_running` 标志。
- **3. 管道创建:** `named_pipe_listener_stream.rs:37-45` 使用 `ServerOptions::new().create(PIPE_NAME)` 创建初始管道实例。失败时取消 token 并终止。
- **4. 接受循环:** `named_pipe_listener_stream.rs:46-86` 在 `tokio::select!` 中等待取消或新连接。
- **5. PID 获取:** `named_pipe_listener_stream.rs:55-61` 通过 `GetNamedPipeClientProcessId(handle, &mut pid)` (unsafe) 获取客户端 PID。**失败时 `continue`，拒绝该连接。**
- **6. 进程解析:** `named_pipe_listener_stream.rs:64-71` 调用 `get_peer_info(pid)`。**失败时同样 `continue`，拒绝连接。**
- **7. 分发:** 通过 mpsc channel 发送 `(NamedPipeServer, PeerInfo)`，然后立即创建新管道实例。

### Unix (macOS + Linux) 流程

- **1. 条件编译:** `mod.rs:19-20` 选择 `unix.rs` 作为 `platform_ssh_agent` 模块。
- **2. 路径解析:** `unix.rs:84-91` 的 `get_socket_path()` 检查 `BITWARDEN_SSH_AUTH_SOCK` 环境变量，回退到默认路径。
- **3. Flatpak 适配:** `unix.rs:98-111` 的 `get_default_socket_path()` 检测 Flatpak 容器环境，调整为 `$HOME/.var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock`。
- **4. 清理与绑定:** `unix.rs:34` 移除残留 socket 文件，`unix.rs:38` 绑定 `UnixListener`，`unix.rs:41` 设置 `0o600` 权限。
- **5. 接受连接:** `peercred_unix_listener_stream.rs:30-49` 在 `poll_next()` 中直接轮询 `UnixListener`。
- **6. PID 获取:** `peercred_unix_listener_stream.rs:32-40` 调用 `stream.peer_cred()` 获取 `UCred`，提取 PID。**失败时回退 `PeerInfo::unknown()`，不拒绝连接。**
- **7. 进程解析:** `peercred_unix_listener_stream.rs:41-44` 调用 `get_peer_info(pid)`。**失败时同样回退 `PeerInfo::unknown()`。**

## 4. Design Rationale

- **安全策略差异:** Windows 实现对无法识别的客户端采取严格拒绝策略（`continue` 跳过连接），Unix 实现采取宽容策略（`PeerInfo::unknown()` 继续处理）。这是两个平台之间最重要的行为差异。
- **macOS 无独立实现:** macOS 与 Linux 完全共享 `unix.rs`，没有任何 macOS 专用代码路径。Flatpak 检测虽未用 `cfg(target_os)` 门控，但因 macOS 上不存在 Flatpak 环境变量，实际上仅影响 Linux。
- **管道 vs Socket 生命周期:** Windows Named Pipe 由内核管理生命周期，无需清理文件；Unix Socket 是文件系统对象，需要显式的 `remove_path()` 清理和 `0o600` 权限设置。
