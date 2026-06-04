# IPC Control Protocol Reference

## 1. Core Summary

SSHWarden 守护进程在 `\\.\pipe\sshwarden-control` Named Pipe（非 Windows：运行时目录下的 Unix socket，权限 0600）上监听 JSON 控制命令。客户端连接后发送一行 JSON，守护进程处理后回写一行 JSON 响应并关闭连接。协议为单命令-单响应模型。支持 13 种命令字符串，涵盖锁定/解锁（自动/Hello/原生/PIN/主密码）/状态（人类可读与 JSON）/同步/遗忘/PIN 设置/停止守护进程/主机绑定对话框。守护进程仅接受同一用户的连接（Unix 校验 peer uid；Windows 管道 DACL 限定当前用户 + SYSTEM）。

## 2. Source of Truth

- **Primary Code:** `crates/sshwarden-agent/src/control.rs` -- 完整的 IPC 服务端和客户端实现，包含数据结构定义、调用方鉴权与命令分发。
- **Business Logic:** `src/main.rs` (`handle_control_command`) -- 各命令的具体处理逻辑。
- **Cache Persistence:** `crates/sshwarden-config/src/cache.rs` (`LocalKeyCacheFile`，信封格式 v3，含 `pin_salt`) 与旧版 `crates/sshwarden-config/src/vault.rs` (`VaultFile`)。
- **Hello Crypto:** `crates/sshwarden-ui/src/unlock/hello_crypto.rs` -- Hello 签名路径加解密。
- **Configuration:** `crates/sshwarden-config/src/lib.rs` -- 相关配置项（`lock_timeout`, `auto_unlock_on_request`）及数据目录解析（`config_dir()` 默认平台标准目录，便携模式可选，见 `resolve_data_dir`）。
- **Related Architecture:** `/llmdoc/architecture/ipc-control-channel.md` -- IPC 通道架构文档。

## 3. Protocol Details

### Pipe Address

`\\.\pipe\sshwarden-control` -- 参见 `crates/sshwarden-agent/src/control.rs:58`.

### Request Format

```json
{"cmd": "<command_string>"}
```

### Command List

`dispatch_control_command` (`crates/sshwarden-agent/src/control.rs`) maps 13
command strings to `ControlAction` variants:

| Command | ControlAction | Description |
|---|---|---|
| `lock` | `Lock` | 清除私钥，锁定密码库 |
| `unlock` | `Unlock` | 自动解锁：原生缓存 -> Hello 信封 -> 旧 Hello 签名路径 -> PIN 对话框 |
| `unlock-hello` | `UnlockHello` | 仅 Hello 路径解锁（需缓存含 hello_challenge/hello_encrypted） |
| `unlock-native` | `UnlockNative` | 仅平台原生（Keychain/Secret Service/DPAPI）信封解锁 |
| `unlock-pin:{pin}` | `UnlockPin { pin }` | PIN 解密密钥缓存后重载（信封缓存优先，降级旧 vault.enc）；带失败延迟/锁定 |
| `unlock-password:{password}` | `UnlockPassword { password }` | 主密码重新登录 Bitwarden 并同步密钥 |
| `status` | `Status { json: false }` | 返回锁定状态、密钥数量等（人类可读 message） |
| `status-json` | `Status { json: true }` | 同上，仅返回 `details` JSON |
| `sync` | `Sync` | 重新同步 Bitwarden 密码库（需已认证）；锁定时仅刷新缓存并置 pending_sync |
| `forget` | `Forget` | 删除本地密钥缓存/会话材料并清空 agent |
| `stop` | `Stop` | 干净关闭守护进程（取消主循环、停止 agent 与控制服务、删除 PID 文件）；供 `stop`/`restart` 使用 |
| `set-pin:{pin}` | `SetPin { pin }` | 用 PIN（随机盐，格式 v3）加密当前密钥缓存并持久化，可选注册 Hello/原生 |
| `bind-hosts-dialog` | `BindHostsDialog` | 打开主机绑定管理对话框，对话框关闭后返回 |

### Response Format

```json
{
  "ok": true,
  "message": "optional message",
  "error": "optional error (when ok=false)",
  "locked": true,
  "key_count": 3,
  "details": { "...": "Status/status-json 的结构化字段" }
}
```

- `ok`: 操作是否成功。
- `message`: 成功时的描述信息。
- `error`: 失败时的错误描述。
- `locked` / `key_count`: 仅 `status` 命令返回。
- `details`: 仅 `status`/`status-json` 返回，含 `locked`、`key_count`、`signable_key_count`（可签名密钥数，锁定时为 0）、`agent_running`（SSH 端点是否在服务）、`has_pin`、`has_vault_file`、`has_local_key_cache`、`legacy_migration_available`、`authenticated`、`pending_sync`、`data_dir`（解析出的数据目录）、`notification`。

所有字段除 `ok` 外均为 optional（`#[serde(skip_serializing_if = "Option::is_none")]`）。
