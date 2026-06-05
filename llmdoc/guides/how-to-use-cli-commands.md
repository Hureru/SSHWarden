# How to Use SSHWarden CLI Commands

SSHWarden 提供一个 SSH Agent 守护进程和一组 CLI 子命令。守护进程处理 SSH Agent 请求；CLI 子命令通过 IPC 控制通道与运行中的 agent 通信，或直接读写本地文件。命令按用途分为五组：① 进程生命周期 ② Vault 会话（联网）③ 锁定状态（离线）④ Key 与 Host 绑定（离线）⑤ 集成（本机设置）。解锁方式：Windows Hello / 平台原生、PIN；主密码仅用于 `login`。

**数据目录解析（4 层优先级，见 `crates/sshwarden-config/src/lib.rs` `resolve_data_dir`）：** ① 环境变量 `SSHWARDEN_HOME`；② `SSHWARDEN_PORTABLE=1` → exe 所在目录；③ exe 同目录 `config.toml` 中 `[storage] portable = true`（可选 `portable_dir`）→ 便携目录；④ **默认：平台标准目录**（Windows `%APPDATA%\SSHWarden`、Linux `$XDG_CONFIG_HOME/sshwarden` 或 `~/.config/sshwarden`、macOS `~/Library/Application Support/SSHWarden`）。所有数据文件（`config.toml`、`local-key-cache.json`、旧版 `vault.enc`、`sshwarden.log`、`sshwarden.pid`、`session-*.enc`）都存放在解析出的该目录下。运行 `sshwarden status` 可查看实际解析出的 `data_dir`。

## ① 进程生命周期

1. **启动 agent:** `sshwarden run`（前台，Ctrl-C 停止）或 `sshwarden run --background`（后台）。直接运行 `sshwarden`（无子命令）等价于 `sshwarden run`。若数据目录下存在 `local-key-cache.json`（或旧版 `vault.enc`），agent 直接启动并进入锁定状态，等待 Hello/PIN/原生 解锁；若无缓存，提示输入 Bitwarden 主密码登录后加载密钥。参见 `src/main.rs` `run_foreground`.

2. **停止 / 重启:** `sshwarden stop` 经控制通道请求 agent 干净关闭并等待其释放 PID 文件（对未运行的 agent 幂等，退出码 0）。`sshwarden restart` 先停止再以后台方式重新拉起（`run --background`）。

3. **查看状态:** `sshwarden status` 显示一屏可读摘要（Agent / Device / Lock / Bitwarden / Sync / Keys）与建议的下一步；agent 未运行时回退为本地文件视图。`sshwarden status --json` 打印原始机器可读 JSON。

4. **诊断:** `sshwarden doctor` 运行只读检查；`sshwarden doctor --fix` 执行安全修复（例如向 `~/.ssh/config` 写入 SSHWarden Include 行）。

## ② Vault 会话（联网）

5. **登录 / 引导:** `sshwarden login` 将主密码经控制通道交给运行中的 agent，由其登录 Bitwarden、同步并加载密钥；若本机尚无 Remembered Device，CLI 会在客户端提示设置 PIN（经 `set-pin` 写入信封缓存，完成 Remembered Device）。无 agent 运行时退化为仅列出密钥并提示先 `run --background`。

6. **手动同步:** `sshwarden sync`。agent 用缓存的 Bitwarden API 客户端重新同步密钥（需已认证）；锁定时仅刷新缓存并置 pending_sync。

7. **遗忘:** `sshwarden forget` 删除本机记住的密钥缓存 / 会话 / PIN / 原生材料，下次需重新登录。

## ③ 锁定状态（离线）

8. **锁定:** `sshwarden lock`。清除内存私钥（公钥身份保留可列出）。

9. **解锁:** `sshwarden unlock` 默认 `--method auto`（先平台解锁，再降级到 PIN 对话框）。可显式 `--method pin` / `--method hello` / `--method native`。主密码不再用于 `unlock`，改由 `login`。

10. **设置 PIN:** `sshwarden set-pin`，输入并确认 PIN（≥4 字符）。agent 用 PIN（随机盐，信封格式 v3）加密当前密钥缓存并持久化，可选注册 Hello / 原生。

## ④ Key 与 Host 绑定（离线）

11. **列出 keys:** `sshwarden keys`（或 `keys list`）离线读取 `local-key-cache.json`，显示每个 key 的身份、绑定的 host、selector 文件是否存在、以及 ssh-config Include 状态。

12. **绑定 / 解绑:** `sshwarden keys bind <key> <host>...` 绑定（key 可用名称或 vault item id）；`sshwarden keys unbind <key> <host>` 解绑单个 host，`--all` 解绑全部。`sshwarden keys ui` 打开图形绑定管理器（需 agent 运行）。

## ⑤ 集成（本机设置）

13. **Shell 环境:** `sshwarden env [--shell sh|fish|powershell|cmd]` 打印 agent 发现用的环境变量导出。

14. **SSH config:** `sshwarden ssh-config` 显示托管 snippet 路径与 Include 状态；`ssh-config show` 打印 snippet；`ssh-config write` 从本地缓存 + 绑定离线重写 snippet 并确保 Include 行；`ssh-config remove` 移除 Include 行（snippet 文件保留）。snippet 默认写在 exe 同目录的 `sshwarden_config`，可用 `config.toml` 的 `[ssh_config].managed_path` 覆盖，支持 `~` 展开。

15. **开机自启动:** `sshwarden startup enable` 安装平台自启动项（Windows 启动文件夹 .lnk、Linux XDG autostart、macOS LaunchAgent），目标为 `<exe> run --background`，WorkingDirectory 设为 exe 同目录；若本机尚无 Remembered Device 会拒绝并提示先 `login`。`sshwarden startup disable` 移除自启动项。

16. **配置:** `sshwarden config` 显示配置文件路径（不存在则创建默认）。

**验证:** 使用 `ssh -T git@github.com` 触发 SSH 签名请求，确认授权对话框 / 通知正确显示密钥名和操作类型。
