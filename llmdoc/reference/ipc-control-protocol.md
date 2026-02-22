# IPC Control Protocol Reference

## 1. Core Summary

SSHWarden 守护进程在 `\\.\pipe\sshwarden-control` Named Pipe 上监听 JSON 控制命令。客户端连接后发送一行 JSON，守护进程处理后回写一行 JSON 响应并关闭连接。协议为单命令-单响应模型。支持 8 种命令，涵盖锁定/解锁（3 种路径）/状态查询/同步/PIN 设置。

## 2. Source of Truth

- **Primary Code:** `crates/sshwarden-agent/src/control.rs` -- 完整的 IPC 服务端和客户端实现，包含数据结构定义。
- **Business Logic:** `src/main.rs:508-943` (`handle_control_command`) -- 各命令的具体处理逻辑。
- **Vault Persistence:** `crates/sshwarden-config/src/vault.rs` (`VaultFile`) -- vault.enc 文件读写。
- **Hello Crypto:** `crates/sshwarden-ui/src/unlock/hello_crypto.rs` -- Hello 签名路径加解密。
- **Configuration:** `crates/sshwarden-config/src/lib.rs` -- 相关配置项（`lock_timeout`, `auto_unlock_on_request`）及便携路径解析（`config_dir()` 基于 exe 所在目录）。
- **Related Architecture:** `/llmdoc/architecture/ipc-control-channel.md` -- IPC 通道架构文档。

## 3. Protocol Details

### Pipe Address

`\\.\pipe\sshwarden-control` -- 参见 `crates/sshwarden-agent/src/control.rs:58`.

### Request Format

```json
{"cmd": "<command_string>"}
```

### Command List

| Command | ControlAction | Description |
|---|---|---|
| `lock` | `Lock` | 清除私钥，锁定密码库 |
| `unlock` | `Unlock` | 自动解锁：优先 Hello 签名路径 -> 降级 Hello UV -> 从内存缓存重载 |
| `unlock-hello` | `UnlockHello` | 仅 Hello 签名路径解锁（需 vault.enc 含 hello_challenge） |
| `unlock-pin:{pin}` | `UnlockPin { pin }` | PIN 解密密钥缓存后重载（优先内存，降级 vault.enc） |
| `unlock-password:{password}` | `UnlockPassword { password }` | 主密码重新登录 Bitwarden 并同步密钥 |
| `status` | `Status` | 返回锁定状态、密钥数量、PIN/vault.enc 状态 |
| `sync` | `Sync` | 重新同步 Bitwarden 密码库（需已认证） |
| `set-pin:{pin}` | `SetPin { pin }` | 用 PIN 加密当前密钥缓存，持久化到 vault.enc，可选注册 Hello 签名路径 |

### Response Format

```json
{
  "ok": true,
  "message": "optional message",
  "error": "optional error (when ok=false)",
  "locked": true,
  "key_count": 3
}
```

- `ok`: 操作是否成功。
- `message`: 成功时的描述信息。Status 命令附加 PIN/vault.enc 状态。
- `error`: 失败时的错误描述。
- `locked`: 仅 `status` 命令返回，当前锁定状态。
- `key_count`: 仅 `status` 命令返回，当前加载的密钥数量。

所有字段除 `ok` 外均为 optional（`#[serde(skip_serializing_if = "Option::is_none")]`）。
