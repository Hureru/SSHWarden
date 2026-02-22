# How to Use SSHWarden CLI Commands

SSHWarden 提供守护进程模式和多个 CLI 子命令。守护进程处理 SSH Agent 请求，CLI 子命令通过 IPC 控制通道与守护进程通信。支持三种解锁路径：Windows Hello 签名、PIN、主密码。所有数据文件（config.toml、vault.enc、sshwarden.log、sshwarden.pid）均存放在 exe 所在目录（完全便携模式）。

1. **启动守护进程:** 运行 `sshwarden`（无子命令）。若 exe 同目录下存在 vault.enc 文件，守护进程直接启动并进入锁定状态，等待 Hello/PIN/Password 解锁；若无 vault.enc，程序提示输入 Bitwarden 主密码，登录后加载 SSH 密钥。确认输出 `SSH Agent is running` 即表示就绪。参见 `src/main.rs:323-504`.

2. **查看状态:** 运行 `sshwarden status`。显示锁定状态（locked/unlocked）、密钥数量、是否配置 PIN、是否有 vault.enc 文件。若守护进程未运行则提示连接失败。参见 `src/main.rs:151`.

3. **锁定密码库:** 运行 `sshwarden lock`。守护进程清除内存中的私钥材料（公钥元数据保留），后续签名请求将被拒绝或触发解锁流程。参见 `src/main.rs:135`.

4. **解锁密码库（自动选择）:** 运行 `sshwarden unlock`。守护进程按优先级尝试：先 Hello 签名路径（若 vault.enc 含 hello_challenge），再 Windows Hello UV 验证（需内存缓存），成功后重新加载密钥。参见 `src/main.rs:136-149`.

5. **解锁密码库（Hello 签名路径）:** 运行 `sshwarden unlock --hello`。仅使用 KeyCredentialManager 签名路径解锁。需要先通过 `set-pin` 注册签名路径（Hello 可用时自动注册）。参见 `src/main.rs:145-146`.

6. **解锁密码库（PIN）:** 运行 `sshwarden unlock --pin`，输入之前设置的 PIN。守护进程用 PIN 派生密钥解密缓存的密钥数据并加载到 Agent。支持从 vault.enc 持久化数据解密。参见 `src/main.rs:137-140`.

7. **解锁密码库（主密码）:** 运行 `sshwarden unlock --password`，输入 Bitwarden 主密码。守护进程重新登录 Bitwarden API 并同步最新密钥。适用于密钥已过期或需要更新的场景。参见 `src/main.rs:141-144`.

8. **设置 PIN:** 运行 `sshwarden set-pin`，输入并确认 PIN（至少 4 字符）。守护进程将当前密钥用 PIN 加密后同时存入内存和 exe 同目录下的 vault.enc 文件。若 Windows Hello 可用，自动注册签名路径。参见 `src/main.rs:162`.

9. **手动同步:** 运行 `sshwarden sync`。守护进程使用缓存的 Bitwarden API 客户端重新同步密码库 SSH 密钥。需要守护进程已认证（启动时已登录或通过 `unlock --password` 登录）。参见 `src/main.rs:163`.

10. **安装开机自启动:** 运行 `sshwarden daemon --install`。在用户启动文件夹 (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) 创建 SSHWarden.lnk 快捷方式，目标为 `<exe> daemon`，WorkingDirectory 设为 exe 同目录（保持便携模式）。通过 PowerShell 调用 `WScript.Shell` COM 创建 .lnk 文件。用户登录后快捷方式自动执行，守护进程在用户交互式桌面会话中运行，确保 Toast 通知、Windows Hello 等 UI 交互正常工作。参见 `src/main.rs:1458-1505`.

11. **卸载开机自启动:** 运行 `sshwarden daemon --uninstall`。删除启动文件夹中的 SSHWarden.lnk 快捷方式文件。若文件不存在则提示无需操作。参见 `src/main.rs:1515-1529`.

**验证:** 使用 `ssh -T git@github.com` 触发 SSH 签名请求，确认 Windows Toast 通知弹出并正确显示密钥名和操作类型。
