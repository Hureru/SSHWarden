# PIN 锁定完整架构

## 1. Identity

- **What it is:** Bitwarden 桌面应用的 PIN 锁定子系统，允许用户设置数字 PIN 来快速解锁应用，替代或补充主密码解锁。
- **Purpose:** 为用户提供便捷但安全的锁屏解锁方式，通过 KDF 密钥派生保护 PIN，与生物识别和主密码机制协调工作。

## 2. Core Components

- `desktop/src/auth/components/set-pin.component.ts` (SetPinComponent): 继承自 `@bitwarden/angular` 的基础 PIN 设置组件，提供 `static open(dialogService)` 方法打开 PIN 设置对话框。
- `desktop/src/auth/components/set-pin.component.html` (PIN 设置 UI): 包含密码输入字段、可选的"重启时需要主密码"复选框和确认/取消按钮。
- `desktop/src/app/accounts/settings.component.ts` (SettingsComponent): 主设置页面，处理 PIN 启用/禁用逻辑、PIN 与生物识别的协调、RemoveUnlockWithPin 策略检查。
- `desktop/src/key-management/lock/services/desktop-lock-component.service.ts` (DesktopLockComponentService): 实现 LockComponentService 接口，聚合解锁选项（PIN、生物识别、主密码）供锁屏使用。
- `desktop/src/key-management/electron-key.service.ts` (ElectronKeyService): 扩展 DefaultKeyService，在存储和清除用户密钥时与生物识别服务协调 PIN 相关的密钥管理。
- `@bitwarden/common` (PinServiceAbstraction): 抽象服务层，定义 PIN 的设置/解除/验证接口（实现来自 common 库）。
- `@bitwarden/common` (BiometricsService, BiometricStateService): 生物识别相关服务，与 PIN 机制共享密钥存储和解锁状态管理。

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 PIN 设置流程

1. **用户交互触发**: 设置页面中用户勾选 PIN 复选框（`form.controls.pin.valueChanges`）。参见 `desktop/src/app/accounts/settings.component.ts:479-487`。
2. **验证 PIN 启用状态**: `pinEnabled$` Observable 检查 `RemoveUnlockWithPin` 策略是否允许 PIN 功能。参见 `desktop/src/app/accounts/settings.component.ts:369-378`。
3. **打开 PIN 设置对话框**: `updatePin(true)` 调用 `SetPinComponent.open(dialogService)`，返回 Observable。参见 `desktop/src/app/accounts/settings.component.ts:604-614`。
4. **用户输入 PIN**: 对话框显示密码输入字段和"requireMasterPasswordOnClientRestart"复选框。参见 `desktop/src/auth/components/set-pin.component.html:10-26`。
5. **PIN 服务处理**: SetPinComponent 调用 PinServiceAbstraction 的设置方法进行 PIN 存储（使用 KDF 加密）。
6. **更新 UI 状态**: 对话框返回布尔值，成功时 `userHasPinSet` 标志设为 true，表单控制更新。参见 `desktop/src/app/accounts/settings.component.ts:613-614`。
7. **菜单刷新**: 发送 "redrawMenu" 消息以更新应用菜单。参见 `desktop/src/app/accounts/settings.component.ts:600`。

### 3.2 PIN 禁用流程

1. **用户取消勾选**: 设置页面中用户取消勾选 PIN 复选框。
2. **Windows 平台特殊处理**: 检查条件：Windows 平台 + 有生物识别 + "重启时需要主密码"启用 + 有生物识别但无主密码。参见 `desktop/src/app/accounts/settings.component.ts:618-628`。
3. **防止用户锁定**: 若满足上述条件，调用 `enrollPersistentBiometricIfNeeded(userId)` 确保生物识别在重启后仍可用，防止用户进入无法解锁的状态。参见 `desktop/src/app/accounts/settings.component.ts:726-734`。
4. **移除 PIN**: 调用 `pinService.unsetPin(userId)` 删除 PIN 配置。参见 `desktop/src/app/accounts/settings.component.ts:629`。
5. **更新状态**: 表单控制刷新，菜单重绘。

### 3.3 PIN 解锁流程

1. **锁屏启动**: 用户在应用锁屏界面。
2. **解锁选项聚合**: `DesktopLockComponentService.getAvailableUnlockOptions$(userId)` 通过 RxJS combineLatest 合并多个 Observable。参见 `desktop/src/key-management/lock/services/desktop-lock-component.service.ts:53-80`。
3. **PIN 可用性检查**: 调用 `defer(() => this.pinService.isPinDecryptionAvailable(userId))`，异步检查该用户是否已设置 PIN。参见 `desktop/src/key-management/lock/services/desktop-lock-component.service.ts:58`。
4. **返回解锁选项**: 返回 `UnlockOptions` 对象，包含 `pin.enabled` 字段表示 PIN 是否可用。参见 `desktop/src/key-management/lock/services/desktop-lock-component.service.ts:65-66`。
5. **用户选择 PIN 解锁**: 用户在锁屏上点击 PIN 按钮。
6. **PIN 验证**: 调用 PinServiceAbstraction 的验证方法，验证输入的 PIN（使用 KDF 派生密钥）。
7. **密钥解密**: PIN 验证成功后，恢复用户的加密主密钥，解锁应用。

### 3.4 PIN 与生物识别的协调

1. **启用生物识别时**: `updateBiometric(true)` 检查 Windows 平台是否需要持久化生物识别密钥。参见 `scout-app-integration.md` 报告。
2. **Windows 特殊逻辑**: 若用户无主密码但有 PIN + 要求重启时需要主密码，则 Windows 自动调用 `enrollPersistentBiometricIfNeeded()` 确保生物识别在重启后可用。参见 `desktop/src/app/accounts/settings.component.ts:676-687`。
3. **"重启时需要主密码"选项**: 当用户启用生物识别且有主密码或 PIN 时，此选项显示。选项控制应用重启后是否需要主密码/PIN 验证（而非自动通过生物识别解锁）。参见 `desktop/src/app/accounts/settings.component.ts:714-724`。
4. **ElectronKeyService 集成**: 当用户添加新的解锁密钥时，`storeAdditionalKeys()` 方法检查生物识别是否启用，若启用则同时调用 `biometricService.setBiometricProtectedUnlockKeyForUser()` 存储生物识别保护的副本。参见 `desktop/src/key-management/electron-key.service.ts:54-60`。

### 3.5 RemoveUnlockWithPin 策略控制

1. **策略检查**: `pinEnabled$` Observable 监听 `PolicyService.policiesByType$(PolicyType.RemoveUnlockWithPin, userId)`。参见 `desktop/src/app/accounts/settings.component.ts:369-378`。
2. **返回值语义**: 当策略存在且启用时，返回 `false`（PIN 被禁用）；当策略不存在或禁用时，返回 `true`（PIN 启用）。参见 `desktop/src/app/accounts/settings.component.ts:375-376`。
3. **UI 条件渲染**: 设置页面根据 `(pinEnabled$ | async)` 和 `userHasPinSet` 共同决定是否显示 PIN 复选框。参见 `desktop/src/app/accounts/settings.html:79-86`。

### 3.6 清除 PIN 时的密钥清理

1. **触发场景**: 用户注销或账户切换。
2. **ElectronKeyService 清除**: 调用 `clearAllStoredUserKeys(userId)` 时，先调用 `biometricService.deleteBiometricUnlockKeyForUser(userId)` 移除生物识别保护的密钥副本。参见 `desktop/src/key-management/electron-key.service.ts:77-80`。
3. **PinService 清除**: 同时调用 `pinService.logout(userId)` 移除该账户的 PIN 状态（在 app.component.ts 中）。参见 `scout-app-integration.md` 报告第 732-733 行。

## 4. Design Rationale

- **PIN 与 KDF**: PIN 通过 KDF（密钥派生函数）加密存储，安全性取决于 KDF 迭代次数和用户 PIN 的强度。
- **三解锁方案协调**: PIN、生物识别和主密码是互补的解锁选项。生物识别需要设备硬件支持；主密码是最强保证；PIN 提供便捷快速的中间选项。
- **Windows 自动生物识别持久化**: Windows 平台在用户禁用 PIN 但保留生物识别时，自动创建持久化生物识别密钥，避免用户陷入无法解锁的状态（若无主密码且禁用了 PIN）。
- **政策约束**: RemoveUnlockWithPin 策略允许组织级别禁用 PIN 功能，适用于管理者想要强制使用更强身份验证方式的场景。
- **"重启时需要主密码"语义**: 此选项控制的是应用重启后的解锁行为，与运行中应用的锁定行为无关。启用时强制用户在重启后输入主密码或 PIN；禁用时允许生物识别自动解锁。
