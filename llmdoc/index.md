# SSHWarden 完整文档索引

**项目**: SSHWarden -- Bitwarden SSH Agent (独立 CLI)
**版本**: Phase 5 complete
**License**: GPL-3.0
**技术栈**: Pure Rust (Tokio + Clap + Slint + winit + WinRT + bitwarden-russh)

---

## 快速导航路径

### 新手入门
如果你是第一次接触本项目，建议按以下顺序阅读：

1. **项目身份与使命**
   - `overview/project-overview.md` - SSHWarden 是什么、技术栈、crate 结构、实现阶段

2. **核心架构理解**
   - `architecture/sshwarden-main-loop.md` - 双线程架构（Slint 主线程 + tokio 线程）tokio::select! 四路事件处理
   - `architecture/ipc-control-channel.md` - IPC 控制通道架构（Named Pipe JSON 协议，8 种命令）
   - `architecture/slint-authorization-dialog.md` - Slint 跨平台授权对话框（SSH 签名请求 Approve/Deny）
   - `architecture/sshwarden-windows-hello-unlock.md` - Windows Hello 解锁（签名路径 + Slint PIN 对话框降级）
   - `architecture/sshwarden-pin-encryption.md` - PIN 加解密架构 + vault.enc 持久化

3. **操作指南**
   - `guides/how-to-use-cli-commands.md` - CLI 命令使用指南（启动/锁定/三路径解锁/PIN/sync）

4. **参考信息**
   - `reference/ipc-control-protocol.md` - IPC 控制协议参考（8 种命令、请求/响应格式）

### 架构开发者查询表

按你要解决的问题查找对应文档：

| 问题 | 文档 |
|------|------|
| "项目是什么，crate 结构如何？" | `overview/project-overview.md` |
| "守护进程主循环如何工作？" | `architecture/sshwarden-main-loop.md` |
| "双线程架构怎么工作？" | `architecture/sshwarden-main-loop.md` (3.1 节) |
| "SSH 签名请求如何授权？" | `architecture/slint-authorization-dialog.md` |
| "Windows Hello 解锁如何工作？" | `architecture/sshwarden-windows-hello-unlock.md` |
| "Hello 签名路径是什么？" | `architecture/sshwarden-windows-hello-unlock.md` (3.1 节) |
| "PIN 对话框 validator 重试模式如何工作？" | `architecture/sshwarden-windows-hello-unlock.md` (3.2 节) |
| "PIN 对话框降级如何工作？" | `architecture/sshwarden-windows-hello-unlock.md` (3.2 节) |
| "make_pin_validator 和 decrypted_cache 如何避免重复 KDF？" | `architecture/sshwarden-windows-hello-unlock.md` (3.2 节) + `architecture/sshwarden-pin-encryption.md` (3.2 节) |
| "Slint PIN 对话框如何跨线程调度？" | `architecture/sshwarden-windows-hello-unlock.md` (3.2 节) + `architecture/sshwarden-main-loop.md` (3.1 节) |
| "Slint 授权对话框如何工作？" | `architecture/slint-authorization-dialog.md` |
| "UIRequest 枚举如何统一 UI 请求？" | `architecture/sshwarden-main-loop.md` (2 节 UIRequest) + `architecture/slint-authorization-dialog.md` (3.2 节) |
| "PIN 加解密如何实现？" | `architecture/sshwarden-pin-encryption.md` |
| "vault.enc 持久化如何工作？" | `architecture/sshwarden-pin-encryption.md` (3.1 步骤 6-7) |
| "IPC 控制通道如何通信？" | `architecture/ipc-control-channel.md` |
| "CLI 命令有哪些？怎么用？" | `guides/how-to-use-cli-commands.md` |
| "IPC 协议的具体格式？" | `reference/ipc-control-protocol.md` |

---

## 完整文档清单

### Overview - 项目概览

#### 1. `overview/project-overview.md`
**身份**: SSHWarden -- Bitwarden SSH Agent
**内容**: 项目定义、技术栈（Rust + Tokio + Clap + Slint + WinRT）、5 个 crate 的职责、5 个实现阶段状态、关键设计决策
**适用角色**: 任何人 - 快速了解项目

---

### Architecture - 系统构建方式

#### 2. `architecture/sshwarden-main-loop.md`
**身份**: SSHWarden 守护进程双线程架构（Slint 主线程 + tokio 线程）
**内容**: 双线程启动流程（main -> Slint 事件循环 + tokio 线程）、UIRequest 统一通道桥接（mpsc + slint::invoke_from_event_loop，PinDialog 携带 validator 闭包、AuthDialog）、tokio::select! 四路事件（control/request/lock-check/ctrl-c）、8 种控制命令处理、get_pin_encrypted_data/make_pin_validator 辅助函数、二级自动解锁、关闭流程（channel drop -> quit_event_loop）
**适用角色**: 核心架构开发

#### 3. `architecture/slint-authorization-dialog.md`
**身份**: Slint 跨平台授权对话框
**内容**: SSH 签名请求授权 UI（替代原 Windows Toast 通知 + TaskDialog/MessageBox）、AuthDialog 窗口组件（进程名/密钥名/操作类型/代理转发警告/Approve+Deny）、UIRequest::AuthDialog 跨线程调度（request_authorization -> bridge -> show_auth_dialog）、3 处调用点（Hello 签名路径后/PIN 解锁后/正常签名）
**适用角色**: UI 开发、授权流程开发

#### 4. `architecture/sshwarden-windows-hello-unlock.md`
**身份**: SSHWarden 的 Windows Hello 解锁流程（签名路径 + Slint PIN 对话框降级 + validator 重试模式）
**内容**: 签名路径（KeyCredentialManager）、Slint PIN 对话框降级路径（validator 闭包注入、后台线程验证、错误重试、抖动+红色提示、decrypted_cache 缓存避免重复 KDF）、`get_pin_encrypted_data()`/`make_pin_validator()` 辅助函数、SSH 请求自动解锁优先级（签名 -> PIN 对话框 -> 拒绝）、hello_crypto 模块
**适用角色**: 解锁流程开发

#### 5. `architecture/ipc-control-channel.md`
**身份**: IPC 控制通道架构
**内容**: Named Pipe 服务端/客户端、JSON 命令解析、ControlAction 枚举（8 种变体）、oneshot 回复通道、CancellationToken 关闭
**适用角色**: IPC 通信开发

#### 6. `architecture/sshwarden-pin-encryption.md`
**身份**: PIN 加解密 + vault.enc 持久化架构
**内容**: Argon2id PIN 密钥派生（64 MiB/3 iter）、AES-256-CBC + HMAC-SHA256 加密、type 2 EncString 格式、vault.enc 文件结构（VaultFile）、PIN 设置/解锁流程、Hello 签名路径注册
**适用角色**: 加密/安全/持久化开发

---

### Guides - 操作指南

#### 7. `guides/how-to-use-cli-commands.md`
**目的**: SSHWarden CLI 命令完整使用指南
**内容**: 守护进程启动（含 vault.enc 自动检测）、status/lock/unlock（自动/Hello/PIN/password）/set-pin/sync/daemon --install/daemon --uninstall 十一个操作步骤
**适用角色**: 开发者、用户、测试

---

### Reference - 查询参考

#### 8. `reference/ipc-control-protocol.md`
**身份**: IPC 控制协议参考
**内容**: Pipe 地址、请求格式（JSON ControlCommand）、8 种命令映射表（含 unlock-hello/unlock-password）、响应格式（ControlResponse 字段说明）
**适用角色**: IPC 协议调试、客户端开发

---

## Legacy Documentation (Bitwarden Desktop 参考)

以下文档来自对 Bitwarden Desktop 客户端（Electron + Angular）SSH Agent 的分析，作为 SSHWarden 的设计参考保留。这些文档中的代码路径指向 Bitwarden Desktop 仓库，不是 SSHWarden 的源码。

### Overview
- `overview/ssh-agent-architecture-overview.md` - Bitwarden Desktop SSH Agent 三层架构

### Architecture
- `architecture/ssh-agent-authorization-flow.md` - Bitwarden Desktop 授权决策树
- `architecture/ssh-agent-platform-implementations.md` - 多平台实现
- `architecture/ssh-agent-key-management.md` - 密钥管理
- `architecture/ssh-agent-data-flow.md` - 13 步数据流
- `architecture/windows-hello-biometric-flow.md` - Bitwarden Desktop Windows Hello 实现（Ephemeral + Persistent 双路径）
- `architecture/pin-lock-architecture.md` - Bitwarden Desktop PIN 锁定架构
- `architecture/biometric-cross-platform-architecture.md` - 跨平台生物识别
- `architecture/biometric-pin-app-integration.md` - 应用层集成

### Guides
- `guides/how-ssh-request-approval-works.md` - 审批交互
- `guides/how-ssh-keys-are-protected.md` - 密钥保护
- `guides/how-ssh-agent-starts.md` - 启动流程
- `guides/how-windows-hello-unlock-works.md` - Bitwarden Desktop Windows Hello 用户指南
- `guides/how-pin-lock-works.md` - Bitwarden Desktop PIN 用户指南
- `guides/how-to-configure-biometric-and-pin.md` - Bitwarden Desktop 配置指南

### Reference
- `reference/coding-conventions.md` - 编码规范
- `reference/git-conventions.md` - 仓库信息
- `reference/platform-comparison-table.md` - 平台对照表
- `reference/ssh-agent-ipc-channels.md` - Bitwarden Desktop 7 个 IPC 通道
- `reference/biometric-platform-comparison.md` - 生物识别平台对比

---

## 文档统计

| 类别 | SSHWarden 专属 | Legacy (Bitwarden Desktop 参考) | 总计 |
|------|------|------|------|
| **Overview** | 1 | 1 | 2 |
| **Architecture** | 5 | 8 | 13 |
| **Guides** | 1 | 6 | 7 |
| **Reference** | 1 | 5 | 6 |
| **总计** | **8** | **20** | **28** |

---

## 文档更新日志

**最后更新**: 2026-03-10

### PIN 对话框 validator 重试模式（错误 PIN 保持打开并提示重试）
- UPDATE `architecture/sshwarden-windows-hello-unlock.md` - PIN 对话框从"提交即关闭"改为 validator 注入重试模式：`UIRequest::PinDialog` 新增 `validator` 字段，对话框在后台线程验证 PIN（`std::thread::spawn` + `invoke_from_event_loop`），失败时保持打开（清空输入+红色提示+抖动动画），`tx_cell` 从 `Rc<RefCell>` 改为 `Arc<Mutex>` 支持跨线程。新增 `get_pin_encrypted_data()`/`make_pin_validator()` 辅助函数，`decrypted_cache` 避免重复 Argon2id KDF
- UPDATE `architecture/sshwarden-main-loop.md` - `UIRequest::PinDialog` 变体新增 `validator` 字段描述，bridge 线程解构透传 validator，新增 `get_pin_encrypted_data`/`make_pin_validator` 组件，更新 select! 事件和 Design Rationale（validator 注入模式）
- UPDATE `architecture/sshwarden-pin-encryption.md` - PIN 解锁流程拆分为 CLI 入口和 PIN 对话框入口（validator 重试模式），新增 `make_pin_validator` + `decrypted_cache` 取回解密结果流程
- UPDATE `architecture/slint-authorization-dialog.md` - 标注 AuthDialog 仍用 `Rc<RefCell>` 而 PinDialog 已改为 `Arc<Mutex>` 的差异
- UPDATE `overview/project-overview.md` - PIN 对话框降级设计决策新增 validator 注入模式、后台线程验证、错误重试、decrypted_cache 缓存描述
- UPDATE `llmdoc/index.md` - 新增 validator/make_pin_validator 查询表条目、更新文档描述、新增更新日志

### Slint 窗口居中+聚焦跨平台改造 & AuthDialog UI 美化
- UPDATE `architecture/slint-authorization-dialog.md` - `center_and_focus_dialog()` 改为跨平台（移除 `#[cfg]`，使用 winit `focus_window()`），延迟调度改为 `Timer::single_shot(30ms)`，UI 属性更新（380x195px、Segoe UI 字体、22px 进程名、13px 正文、16px 内边距、30px 按钮高度）
- UPDATE `architecture/sshwarden-windows-hello-unlock.md` - PinDialog 新增 `center_and_focus_dialog` 跨平台居中+聚焦描述，Design Rationale 新增 winit 访问器条目
- UPDATE `overview/project-overview.md` - 技术栈 UI 层新增 winit (via WinitWindowAccessor) 和窗口居中+聚焦描述
- UPDATE `llmdoc/index.md` - 技术栈新增 winit，新增更新日志

### Slint 授权对话框替代 Windows Toast 通知（跨平台 UI 统一）
- RENAME `architecture/windows-toast-notification-flow.md` -> `architecture/slint-authorization-dialog.md` - 重写为 Slint 跨平台授权对话框架构，替代 Windows Toast 通知 + TaskDialog + MessageBox fallback + non-Windows 自动批准
- UPDATE `overview/project-overview.md` - UI 层描述从 Toast 通知/MessageBox 改为 Slint 授权对话框，双线程架构从 PinDialogRequest 改为 UIRequest 统一枚举
- UPDATE `architecture/sshwarden-main-loop.md` - bridge 线程从 PinDialogRequest 改为 UIRequest match 分发（PinDialog + AuthDialog），新增 UIRequest/show_auth_dialog/request_authorization 组件
- UPDATE `architecture/sshwarden-windows-hello-unlock.md` - 签名路径后授权从 spawn_blocking+TaskDialog 改为 async request_authorization，PIN 降级后新增授权对话框步骤，跨线程通信改为 UIRequest 枚举
- UPDATE `llmdoc/index.md` - 文件重命名、查询表新增授权对话框/UIRequest 条目、文档描述更新

### Slint GUI 框架替代 Win32 PIN 对话框（跨平台 + 双线程架构）
- UPDATE `overview/project-overview.md` - 技术栈新增 Slint，High-Level Description 改为双线程模型，UI 层 PIN 对话框从 Win32 Acrylic 改为 Slint 跨平台，crate 描述更新，新增"双线程架构"设计决策，PIN 对话框降级描述改为 Slint
- UPDATE `architecture/sshwarden-main-loop.md` - 重写为双线程架构：主线程 Slint 事件循环 + tokio 独立线程，新增 `run_slint_event_loop`/bridge 线程/`PinDialogRequest` 通道组件，关闭流程新增 channel drop -> quit_event_loop，更新所有代码行号引用
- UPDATE `architecture/sshwarden-windows-hello-unlock.md` - PIN 对话框从 Win32 原生改为 Slint 跨平台实现，移除 3.3 PIN 对话框 UI 实现节（Win32 细节），降级路径改为 `request_pin_dialog()` 异步请求 Slint 主线程，新增跨线程通信描述（mpsc + oneshot + invoke_from_event_loop），Design Rationale 新增"Slint 替代 Win32"条目
- UPDATE `llmdoc/index.md` - 技术栈新增 Slint，更新文档描述、查询表新增双线程/Slint 条目、新增更新日志

### CredUI 降级移除 + PIN 对话框添加（Windows Hello 解锁流程重构）
- UPDATE `architecture/sshwarden-windows-hello-unlock.md` - 重写为签名路径 + PIN 对话框降级架构：移除 UV 路径用于自动解锁（vault.enc 启动后 cached_key_tuples 为空，UV 无用），移除 CredUI 降级（无锁屏密码 PC 上失败），新增 Win32 原生 PIN 对话框（Acrylic 暗色主题、DPI-aware、键盘快捷键），更新自动解锁优先级（签名 -> PIN 对话框 -> 拒绝）
- UPDATE `overview/project-overview.md` - Tech Stack UI 层新增 PIN 输入对话框描述，Key Design Decisions 更新为"签名路径 + PIN 对话框降级"
- UPDATE `architecture/sshwarden-main-loop.md` - 更新自动解锁描述（二级：Hello 签名 -> PIN 对话框），更新代码行号引用
- UPDATE `llmdoc/index.md` - 新增 PIN 对话框查询表条目、更新 Windows Hello 文档描述、新增更新日志

### 自启动机制变更（Task Scheduler -> 启动文件夹快捷方式）
- UPDATE `guides/how-to-use-cli-commands.md` - 新增步骤 10/11：daemon --install/--uninstall 创建/删除启动文件夹快捷方式
- UPDATE `overview/project-overview.md` - Key Design Decisions 新增"启动文件夹自启动"条目
- UPDATE `architecture/sshwarden-main-loop.md` - Design Rationale 新增启动文件夹自启动说明
- UPDATE `llmdoc/index.md` - 新增自启动机制变更日志

### 便携模式文档更新（exe 同目录路径变更）
- UPDATE `overview/project-overview.md` - 新增"完全便携模式"设计决策、更新 Config & Vault 层和 sshwarden-config crate 描述
- UPDATE `architecture/sshwarden-main-loop.md` - vault.enc 检测描述明确指向 exe 同目录
- UPDATE `architecture/sshwarden-pin-encryption.md` - vault.enc 存储位置明确为 exe 同目录、VaultFile 组件描述更新
- UPDATE `guides/how-to-use-cli-commands.md` - 开头说明所有数据文件在 exe 同目录（完全便携模式）、启动和 set-pin 步骤明确文件位置
- UPDATE `reference/ipc-control-protocol.md` - Configuration 条目补充便携路径解析说明
- UPDATE `llmdoc/index.md` - 新增便携模式更新日志

### Phase 5 文档更新（密钥持久化 + 多路径解锁）
- UPDATE `overview/project-overview.md` - 新增 Phase 5、更新技术栈描述、新增 vault.enc 和 Hello 双路径设计决策
- UPDATE `architecture/sshwarden-pin-encryption.md` - PIN 加密现在持久化到 vault.enc、新增 VaultFile 组件、双重存储流程、Hello 签名路径注册
- UPDATE `architecture/sshwarden-windows-hello-unlock.md` - 重写为双路径架构（UV + KeyCredentialManager 签名路径）、新增自动解锁优先级
- UPDATE `architecture/sshwarden-main-loop.md` - 启动时 vault.enc 检测、8 种控制命令、新增 finish_unlock_with_json/try_hello_unlock 组件
- UPDATE `architecture/ipc-control-channel.md` - 新增 UnlockHello/UnlockPassword 命令、ControlAction 枚举扩展为 8 种
- UPDATE `reference/ipc-control-protocol.md` - 新增 unlock-hello/unlock-password 命令、更新命令列表为 8 种
- UPDATE `guides/how-to-use-cli-commands.md` - 新增 unlock --hello/--password 步骤、更新启动描述（vault.enc 检测）
- UPDATE `llmdoc/index.md` - 更新版本为 Phase 5、更新文档描述、新增查询表条目、新增更新日志

### Phase 3/4 文档更新
- UPDATE `overview/project-overview.md` - 重写为 SSHWarden 独立项目概览（crate 结构、阶段状态）
- CREATE `architecture/sshwarden-main-loop.md` - 守护进程主循环 tokio::select! 架构
- CREATE `architecture/windows-toast-notification-flow.md` - Windows Toast 通知授权流程
- CREATE `architecture/sshwarden-windows-hello-unlock.md` - Windows Hello 解锁流程
- CREATE `architecture/ipc-control-channel.md` - IPC 控制通道架构
- CREATE `architecture/sshwarden-pin-encryption.md` - PIN 加解密架构
- CREATE `guides/how-to-use-cli-commands.md` - CLI 命令使用指南
- CREATE `reference/ipc-control-protocol.md` - IPC 控制协议参考

### 保留的 Bitwarden Desktop 参考文档
所有原有文档保留为 Legacy 参考，不做修改。

---

**文档维护**: 本索引应在每次新增/修改文档时同步更新。
