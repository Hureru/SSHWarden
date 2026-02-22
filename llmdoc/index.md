# SSHWarden 完整文档索引

**项目**: SSHWarden -- Bitwarden SSH Agent (独立 CLI)
**版本**: Phase 5 complete
**License**: GPL-3.0
**技术栈**: Pure Rust (Tokio + Clap + WinRT + bitwarden-russh)

---

## 快速导航路径

### 新手入门
如果你是第一次接触本项目，建议按以下顺序阅读：

1. **项目身份与使命**
   - `overview/project-overview.md` - SSHWarden 是什么、技术栈、crate 结构、实现阶段

2. **核心架构理解**
   - `architecture/sshwarden-main-loop.md` - 守护进程主循环 tokio::select! 四路事件处理
   - `architecture/ipc-control-channel.md` - IPC 控制通道架构（Named Pipe JSON 协议，8 种命令）
   - `architecture/windows-toast-notification-flow.md` - Toast 通知授权流程
   - `architecture/sshwarden-windows-hello-unlock.md` - Windows Hello 解锁（UV + 签名路径双路径）
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
| "SSH 签名请求如何授权？" | `architecture/windows-toast-notification-flow.md` |
| "Windows Hello 解锁如何工作？" | `architecture/sshwarden-windows-hello-unlock.md` |
| "Hello 签名路径是什么？" | `architecture/sshwarden-windows-hello-unlock.md` (3.1 节) |
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
**内容**: 项目定义、技术栈（Rust + Tokio + Clap + WinRT）、5 个 crate 的职责、5 个实现阶段状态、关键设计决策
**适用角色**: 任何人 - 快速了解项目

---

### Architecture - 系统构建方式

#### 2. `architecture/sshwarden-main-loop.md`
**身份**: SSHWarden 守护进程主循环架构
**内容**: 启动初始化流程（vault.enc 检测/条件登录/通道/Agent/状态）、tokio::select! 四路事件（control/request/lock-check/ctrl-c）、8 种控制命令处理、三级自动解锁、关闭流程
**适用角色**: 核心架构开发

#### 3. `architecture/windows-toast-notification-flow.md`
**身份**: Windows Toast 通知授权流程
**内容**: Toast XML 构建（scenario=urgent）、TypedEventHandler 回调（Ref deref + Interface cast）、PowerShell AUMID fallback、MessageBox fallback、60 秒超时
**适用角色**: Windows UI 开发

#### 4. `architecture/sshwarden-windows-hello-unlock.md`
**身份**: SSHWarden 的 Windows Hello 解锁流程（双路径）
**内容**: UV 路径（UserConsentVerifier）、签名路径（KeyCredentialManager + Credential Manager）、SSH 请求自动解锁优先级（签名 -> UV -> 拒绝）、hello_crypto 模块
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

**最后更新**: 2026-02-14

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
