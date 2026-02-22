# SSH 请求审批流程如何运作

从用户视角完整描述 SSH Agent 请求审批的交互流程，涵盖对话框内容、操作类型识别和行为配置。

## 审批对话框交互流程

1. **触发条件:** 当外部 SSH 客户端（如 `ssh`、`git`）发起签名请求时，若 `needsAuthorization()` 返回 `true`，Bitwarden 桌面窗口将被聚焦并弹出审批对话框。对话框由 `ApproveSshRequestComponent` 渲染，见 `desktop/src/autofill/components/approve-ssh-request.ts:51-73` 和 `desktop/src/autofill/components/approve-ssh-request.html`。

2. **对话框显示内容:**
   - **标题:** "Confirm SSH key usage"（i18n: `sshkeyApprovalTitle`）。
   - **请求描述:** "{应用名称} is requesting access to {密钥名称} in order to {操作类型}"，其中应用名称和密钥名称加粗显示。若进程名为空，显示 "An application"（i18n: `unknownApplication`）。
   - **Agent Forwarding 警告:** 仅当 `isAgentForwarding === true` 时显示黄色警告框，标题 "Warning: Agent Forwarding"，内容 "This request comes from a remote device that you are logged into"。
   - **按钮:** "Authorize"（授权，关闭对话框返回 `true`）和 "Deny"（拒绝，关闭对话框返回 `false`）。

3. **三种操作类型的识别规则:**
   - `namespace` 为空或 `null` -> "authenticate to a server"（i18n: `sshActionLogin`）-- 常规 SSH 登录。
   - `namespace === "git"` -> "sign a git commit"（i18n: `sshActionGitSign`）-- Git 提交签名。
   - `namespace` 为其他非空值 -> "sign a message"（i18n: `sshActionSign`）-- 通用 SSHSIG 签名。
   - 操作类型判定逻辑见 `desktop/src/autofill/components/approve-ssh-request.ts:58-63`。

4. **Vault 锁定时的行为:** 若请求到达时 vault 已锁定，系统先聚焦窗口并显示 toast 提示 "Please unlock your vault to approve the SSH key request."（i18n: `sshAgentUnlockRequired`），等待最多 60 秒。超时后显示 "SSH key request timed out."（i18n: `sshAgentUnlockTimeout`），请求被自动拒绝。见 `desktop/src/autofill/services/ssh-agent.service.ts:99-133`。

## 配置提示行为

5. **设置入口:** 在桌面客户端的 Settings 页面中，SSH Agent 区域提供：
   - **Enable SSH Agent** 复选框 -- 全局开关（`sshAgentEnabled$`，跨账户共享）。
   - **Prompt Behavior** 下拉菜单 -- 仅在 SSH Agent 启用时显示，三个选项：
     - **Always** (默认): 每次签名请求都弹出对话框。
     - **Never**: 自动批准所有签名请求（Agent Forwarding 除外）。
     - **Remember Until Lock**: 对每个密钥仅提示一次，直到 vault 锁定、账户切换或应用重启。
   - 见 `desktop/src/app/accounts/settings.component.html:420-452` 和 `desktop/src/app/accounts/settings.component.ts`。

6. **Self-Hosted 支持:** SSH Agent 功能与服务器类型完全无关。不存在任何 feature flag、服务器 URL 检查或自托管限制。该功能在 cloud、self-hosted 和 EU region 上的行为完全一致。见 `/llmdoc/architecture/ssh-agent-authorization-flow.md` 第 4 节 Design Rationale。

7. **验证方式:** 在终端执行 `ssh -T git@github.com` 或 `git commit -S`，观察 Bitwarden 桌面客户端是否弹出审批对话框（取决于当前的 Prompt Behavior 设置）。
