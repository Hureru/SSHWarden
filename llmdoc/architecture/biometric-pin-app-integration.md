# 应用层生物识别与 PIN 集成架构

## 1. Identity

- **What it is:** Renderer 进程中生物识别和 PIN 设置的完整应用集成，涵盖 UI 层、服务层、IPC 通信和主进程状态同步。
- **Purpose:** 提供设置页面 UI 交互、应用初始化、生物识别与 PIN 的启用禁用流程、以及应用生命周期事件的统一管理。

## 2. Core Components

- `desktop/src/app/accounts/settings.component.ts` (SettingsComponent): 核心设置页面组件，包含生物识别和 PIN 的启用/禁用逻辑、表单控制、持久化状态管理和 Windows 平台特殊处理。
- `desktop/src/app/accounts/settings.component.html` (lines 79-137): 安全设置 UI 模板，条件渲染 PIN、生物识别和"重启时需要主密码"复选框，支持 Windows/Linux/macOS 平台差异。
- `desktop/src/app/services/init.service.ts` (InitService.init): 应用启动时的初始化服务，依次调用 SSH Agent、生物识别消息处理和自动解锁密钥设置。
- `desktop/src/app/services/services.module.ts` (Angular DI): 服务注册模块，将 BiometricStateService 和 DesktopBiometricsService 绑定到依赖注入容器。
- `desktop/src/key-management/biometrics/main-biometrics-ipc.listener.ts` (MainBiometricsIPCListener): IPC 消息处理器，监听 Renderer 的生物识别请求并路由到 MainBiometricsService。
- `desktop/src/main/window.main.ts` (WindowMain constructor): 主窗口初始化，在应用关闭前调用 biometricStateService.resetAllPromptCancelled() 重置生物识别提示状态。
- `desktop/src/app/app.component.ts` (AppComponent): 应用根组件，处理登出时的生物识别和 PIN 状态清理。
- `desktop/src/auth/components/set-pin.component.ts` (SetPinComponent): PIN 设置对话框组件，通过 DialogService 打开供用户配置 PIN。

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 生物识别启用流程

1. **UI 交互入口** (settings.component.html:87-97)：用户在设置页面勾选生物识别复选框，触发 `form.valueChanges` 事件。
2. **事件处理** (settings.component.ts:633-643)：`updateBiometricHandler()` 调用 `updateBiometric(true)`。
3. **平台状态检查** (settings.component.ts:645-703)：
   - 调用 `biometricsService.getBiometricsStatus()` 检查生物识别硬件是否可用。
   - 若 `AutoSetupNeeded` 则调用 `setupBiometrics()` 自动设置（Linux）。
   - 若 `ManualSetupNeeded` 则弹出对话框指导用户手动配置。
4. **状态保存** (settings.component.ts:654-675)：调用 `biometricStateService.setBiometricUnlockEnabled(true)`。
5. **Windows 特殊处理** (settings.component.ts:676-687)：
   - 禁用自动提示 (`autoPromptBiometrics = false`)。
   - 若用户无主密码且无 PIN，调用 `enrollPersistentBiometricIfNeeded()` 存储持久化生物识别密钥以支持应用重启时的生物识别解锁。
6. **密钥更新** (settings.component.ts:693)：调用 `keyService.refreshAdditionalKeys(activeUserId)` 同步密钥到生物识别存储。
7. **验证** (settings.component.ts:695-702)：确认生物识别是否成功启用，失败则重置。

### 3.2 生物识别禁用流程

1. **UI 交互** (settings.component.html:87-97)：用户取消勾选生物识别复选框。
2. **禁用处理** (settings.component.ts:652-656)：
   - 调用 `biometricStateService.setBiometricUnlockEnabled(false)`。
   - 调用 `keyService.refreshAdditionalKeys(activeUserId)`。

### 3.3 PIN 启用流程

1. **UI 交互入口** (settings.component.html:79-86)：用户勾选"解锁 PIN"复选框（受 `pinEnabled$` Observable 控制）。
2. **事件处理** (settings.component.ts:592-602)：`updatePinHandler(true)` 调用 `updatePin(true)`。
3. **对话框打开** (settings.component.ts:604-614)：`SetPinComponent.open()` 打开 PIN 设置对话框，用户输入 PIN。
4. **状态更新** (settings.component.ts:613-614)：等待对话框返回结果，更新 `userHasPinSet` 标志。

### 3.4 PIN 禁用流程

1. **UI 交互** (settings.component.html:79-86)：用户取消勾选 PIN 复选框。
2. **禁用处理** (settings.component.ts:615-629)：
   - 调用 `pinService.unsetPin(userId)` 移除 PIN。
   - 在 Windows 上，若用户已启用生物识别、要求重启时需主密码/PIN、但无主密码，调用 `enrollPersistentBiometricIfNeeded()` 防止用户被锁定。

### 3.5 "重启时需要主密码/PIN" 选项的交互逻辑

**显示条件** (settings.component.html:98-121)：
- 生物识别已启用 (`form.value.biometric`)
- Windows 平台 (`isWindows`)
- 用户有主密码或 PIN (`userHasMasterPassword || (form.value.pin && userHasPinSet)`)

**启用处理** (settings.component.ts:714-719)：
- 删除持久生物识别密钥（`deleteBiometricUnlockKeyForUser`）
- 设置标准生物识别密钥（`setBiometricProtectedUnlockKeyForUser`）
- 结果：应用重启时需要主密码或 PIN 解锁

**禁用处理** (settings.component.ts:720-723)：
- 调用 `enrollPersistentBiometricIfNeeded()` 存储持久化生物识别密钥
- 结果：应用重启时可直接使用生物识别解锁，无需主密码/PIN

### 3.6 Renderer ↔ Main IPC 通信

**IPC 通道** (main-biometrics-ipc.listener.ts:17-18)：单一"biometric"通道，支持 13 个 BiometricAction。

**关键 IPC 操作**：
- `SetKeyForUser` (line 35-42)：Renderer 发送 Base64 编码的用户密钥给 Main 进程存储。
- `RemoveKeyForUser` (line 43-46)：Renderer 请求 Main 进程删除用户的生物识别密钥。
- `EnrollPersistent` (line 56-60)：Renderer 请求 Main 进程存储持久化生物识别模板。
- `HasPersistentKey` (line 54-55)：Renderer 查询 Main 进程是否存在持久化密钥。

**消息序列**：
1. Renderer 调用 `ipc.keyManagement.biometric.*` 方法（定义在 preload.ts）。
2. Renderer 进程通过 IPC 发送 BiometricMessage 到 Main 进程。
3. MainBiometricsIPCListener 根据 action 分发到 MainBiometricsService 对应方法。
4. MainBiometricsService 委托给平台特定的 OS 服务（Windows/macOS/Linux）。
5. Main 进程返回结果到 Renderer，Renderer 进程通过 Promise 解析。

### 3.7 应用初始化时的生物识别服务启动

**启动流程** (init.service.ts:60-99)：
1. 加载 SDK 和初始化 Rust 层 (line 62)。
2. 初始化 SSH Agent 服务 (line 63)。
3. 为每个账户设置自动解锁密钥 (lines 68-76)。
4. 调用 `biometricMessageHandlerService.init()` 初始化生物识别消息处理 (line 96)。

### 3.8 账户切换时的状态清理

**登出时清理** (app.component.ts:732-733)：
- 调用 `biometricStateService.logout()` 清除该账户的生物识别状态。
- 调用 `pinService.logout()` 清除该账户的 PIN 状态。

### 3.9 主窗口关闭时的 biometric prompt 重置

**关闭前处理** (window.main.ts:148-150)：
- 应用关闭前（`app.on("before-quit")`）调用 `biometricStateService.resetAllPromptCancelled()`。
- 作用：重置所有 prompt 取消标志，允许下次启动时重新提示生物识别。

## 4. Design Rationale

### 4.1 依赖注入分层

SettingsComponent 注入了 `DesktopBiometricsService` 和 `BiometricStateService` 两个不同的服务：
- **DesktopBiometricsService**：提供高级生物识别操作（启用/禁用、持久化、认证）。
- **BiometricStateService**：管理生物识别的本地状态标志（是否启用、自动提示、取消标志）。

### 4.2 Windows 平台特殊处理

Windows 平台因需要处理应用重启时的无主密码状态，引入了 `enrollPersistentBiometricIfNeeded()` 方法，允许生物识别在应用重启时自动解锁，防止用户陷入无法解锁的状态。

### 4.3 多进程 IPC 模式

Renderer 进程（Angular）通过 IPC 代理调用 Main 进程的生物识别 API，Main 进程再委托给平台特定的 OS 实现。这种设计实现了进程隔离和安全防护。

### 4.4 PIN 与生物识别的互补

PIN 和生物识别并行支持，通过 `requireMasterPasswordOnAppRestart` 选项协调：
- 启用时：应用重启需要主密码或 PIN 解锁。
- 禁用时：应用重启可直接使用生物识别解锁。

### 4.5 策略驱动 UI

PIN 可用性受 `RemoveUnlockWithPin` 组织策略影响，通过 `pinEnabled$` Observable 动态控制 UI 显示，实现灵活的管理员控制。
