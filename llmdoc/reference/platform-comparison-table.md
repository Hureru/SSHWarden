# 平台实现对照表

本文档提供 SSH Agent 在 Windows 与 Unix (macOS/Linux) 平台上的实现差异对照表和 Socket 路径解析算法说明。

## 1. Core Summary

SSH Agent 的平台差异集中在三个维度：IPC 传输机制（Named Pipe vs Unix Socket）、对等进程识别方式（Win32 API vs `SO_PEERCRED`）、以及识别失败时的错误处理策略（拒绝连接 vs 降级为未知身份）。所有平台共享相同的 `peerinfo::gather::get_peer_info()` 进程解析和 `bitwarden_russh::ssh_agent::serve()` 协议处理。

## 2. 完整对照表

| 维度 | Windows | Unix (macOS + Linux) |
|------|---------|---------------------|
| **IPC 传输** | Win32 Named Pipe | Unix Domain Socket |
| **地址** | `\\.\pipe\openssh-ssh-agent`（硬编码） | `$HOME/.bitwarden-ssh-agent.sock`（可配置） |
| **地址可配置性** | 不可配置 | 支持 `BITWARDEN_SSH_AUTH_SOCK` 环境变量覆盖 |
| **Flatpak 适配** | 不适用 | 检测 `container=flatpak`，路径调整为 `$HOME/.var/app/com.bitwarden.desktop/data/` |
| **权限管理** | 依赖 OS 级 Named Pipe ACL（无显式代码） | 显式设置 `fs::Permissions::from_mode(0o600)` |
| **残留文件清理** | 不需要（内核管理管道生命周期） | 启动前调用 `remove_path()` 清理残留 socket |
| **PID 获取方式** | `GetNamedPipeClientProcessId` (Win32 unsafe) | `stream.peer_cred()` (`SO_PEERCRED`) |
| **PID 获取失败行为** | **拒绝连接** (`continue`) | **接受连接**，降级为 `PeerInfo::unknown()` |
| **进程解析失败行为** | **拒绝连接** (`continue`) | **接受连接**，降级为 `PeerInfo::unknown()` |
| **Stream 实现** | `NamedPipeServerStream`（mpsc channel 桥接） | `PeercredUnixListenerStream`（直接 poll `UnixListener`） |
| **连接接受模式** | spawned tokio task + `tokio::select!` 循环 | `poll_next()` 直接轮询 |
| **管道/Socket 重建** | 每次连接后立即创建新管道实例 | 不需要（`UnixListener` 持续接受连接） |
| **创建失败后果** | 取消 token + 设 `is_running=false`，服务终止 | 错误通过 `Result` 向上传播，阻止服务启动 |
| **关键 crate 依赖** | `windows` (Win32_System_Pipes), `pin-project` | `homedir`, `libc` (Linux) / `desktop_objc` (macOS) |
| **共享依赖** | `sysinfo`, `bitwarden_russh`, `tokio`, `futures` | 同左 |

## 3. Unix Socket 路径解析算法

路径解析由 `unix.rs` 中的 `get_socket_path()` 和 `get_default_socket_path()` 实现：

```
1. 检查环境变量 BITWARDEN_SSH_AUTH_SOCK
   -> 若已设置: 直接使用该值作为完整路径（不做任何修改）
   -> 若未设置: 进入步骤 2

2. 获取用户 HOME 目录（via homedir::my_home()）
   -> 失败: 返回错误，服务无法启动

3. 检测 Flatpak 容器环境
   -> 条件: 环境变量 container == "flatpak"
   -> 若是 Flatpak: 路径 = $HOME/.var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock
   -> 若非 Flatpak: 路径 = $HOME/.bitwarden-ssh-agent.sock
```

## 4. Source of Truth

- **Windows 实现:** `desktop/desktop_native/core/src/ssh_agent/windows.rs` 和 `named_pipe_listener_stream.rs`
- **Unix 实现:** `desktop/desktop_native/core/src/ssh_agent/unix.rs` 和 `peercred_unix_listener_stream.rs`
- **条件编译入口:** `desktop/desktop_native/core/src/ssh_agent/mod.rs:18-24`
- **进程信息模型:** `desktop/desktop_native/core/src/ssh_agent/peerinfo/models.rs` (`PeerInfo`)
- **跨平台进程解析:** `desktop/desktop_native/core/src/ssh_agent/peerinfo/gather.rs` (`get_peer_info`)
- **架构文档:** `/llmdoc/architecture/ssh-agent-platform-implementations.md`
