# 如何使用 PIN 锁定机制

本指南说明 PIN 锁定的用户工作流和系统行为。

## 1. 用户设置 PIN

1. 打开应用设置页面（Settings）。
2. 导航到"安全"(Security) 部分的"解锁 PIN"(Unlock with PIN) 选项。
3. 勾选 PIN 复选框。
4. 在弹出的"设置 PIN"对话框中输入所需的 PIN（数字密码）。参见 `desktop/src/auth/components/set-pin.component.html`。
5. **可选**: 若想在应用重启后强制需要主密码或 PIN 验证（而非自动通过生物识别解锁），勾选"重启时需要主密码"复选框。
6. 点击"确定"保存 PIN 设置。
7. PIN 现在已启用，下次应用锁屏时可使用 PIN 解锁。

**注意**: PIN 设置由 `PinServiceAbstraction` 通过 KDF 密钥派生函数安全地存储。

## 2. 用户通过 PIN 解锁应用

1. 应用进入锁屏状态（例如因为 Vault Timeout 或用户手动锁定）。
2. 锁屏界面显示可用的解锁选项。参见 `desktop/src/key-management/lock/services/desktop-lock-component.service.ts:53-80`。
3. 若用户已设置 PIN，锁屏会显示"PIN"按钮（可用性通过 `pinService.isPinDecryptionAvailable(userId)` 检查）。
4. 用户点击 PIN 按钮，输入之前设置的 PIN。
5. PIN 服务验证输入的 PIN 与存储的 PIN（通过 KDF 匹配）。
6. 验证成功，用户主密钥被解密，应用解锁。
7. 若验证失败，用户可重试或选择其他解锁方式（生物识别或主密码）。

## 3. "重启时需要主密码" 选项的行为

此选项控制**应用重启后**的解锁行为，与运行中应用的锁定无关。

### 启用此选项

- **含义**: 应用重启后需要用户输入主密码或 PIN，即使已设置生物识别也需要。
- **场景**: 用户想要在重启后提高安全性，强制进行密码验证。
- **实现**: 调用 `biometricsService.setBiometricProtectedUnlockKeyForUser()` 将用户密钥与生物识别保护相关联，但不创建持久化生物识别密钥。参见 `desktop/src/app/accounts/settings.component.ts:714-724`。

### 禁用此选项

- **含义**: 应用重启后若已启用生物识别，可直接通过生物识别解锁，无需主密码或 PIN。
- **场景**: 用户希望快速启动应用，不愿在每次重启后输入密码。
- **实现**: 调用 `enrollPersistentBiometricIfNeeded(userId)` 为生物识别创建持久化密钥，允许在重启后自动提示生物识别解锁。参见 `desktop/src/app/accounts/settings.component.ts:726-734`。

**注意（Windows 特有）**: 若用户无主密码但有 PIN + 生物识别，禁用此选项时系统会自动创建持久化生物识别密钥，确保用户不会进入无法解锁的状态。参见 `desktop/src/app/accounts/settings.component.ts:618-628`。

## 4. PIN 被禁用的场景

PIN 功能会在以下情况被禁用：

### 4.1 组织政策控制

如果组织管理员启用了 `RemoveUnlockWithPin` 策略，用户将无法使用 PIN 解锁功能。

- **检查方式**: 设置页面的 `pinEnabled$` Observable 监听该策略。参见 `desktop/src/app/accounts/settings.component.ts:369-378`。
- **UI 表现**: PIN 复选框可能被隐藏或禁用，除非用户已经设置过 PIN（已设置的 PIN 仍可使用，但无法新建或修改）。
- **政策定义**: `PolicyType.RemoveUnlockWithPin` 是 Bitwarden 的组织级安全策略。

### 4.2 用户未设置 PIN

若 `pinService.isPinSet(userId)` 返回 false，PIN 解锁选项在锁屏上不会出现。参见 `desktop/src/app/accounts/settings.component.ts:367`。

### 4.3 账户切换/注销

用户注销账户时，`pinService.logout(userId)` 会清除该账户的 PIN 状态，下次登录时需重新设置 PIN。参见 `scout-app-integration.md` 报告。

## 5. PIN 与其他解锁方式的交互

### PIN 与生物识别

- **同时启用**: 用户可同时启用 PIN 和生物识别。锁屏上会显示两个选项供用户选择。
- **协调关系**: ElectronKeyService 会同时存储 PIN 相关的密钥和生物识别相关的密钥。参见 `desktop/src/key-management/electron-key.service.ts:54-60`。
- **重启行为**:
  - 若启用"重启时需要主密码"，应用重启后仍需主密码或 PIN，生物识别不会自动解锁。
  - 若禁用该选项，应用重启后可直接通过生物识别解锁，无需 PIN。

### PIN 与主密码

- **主密码优先级**: 主密码始终是最强的身份验证方式，PIN 和生物识别是替代方案。
- **共存**: 用户可同时拥有主密码和 PIN；在锁屏上可选择任意一种方式解锁。
- **无主密码用户**: 即使用户在 Bitwarden 账户中无主密码设置，仍可使用 PIN 或生物识别解锁桌面应用。

## 6. PIN 与密钥管理的集成

PIN 解锁通过以下方式与密钥管理集成：

- **密钥派生**: PIN 通过 KDF（密钥派生函数）从用户 PIN 输入派生密钥，用于加密/解密用户的主密钥。
- **ElectronKeyService 协调**: 当存储或清除用户密钥时，`ElectronKeyService` 检查是否需要同时管理生物识别保护的副本。参见 `desktop/src/key-management/electron-key.service.ts`。
- **状态隔离**: 不同账户的 PIN 状态完全隔离，切换账户时自动加载对应账户的 PIN 配置。

## 7. 故障排查

### PIN 选项不显示

**原因**:
- 组织启用了 RemoveUnlockWithPin 策略。
- 用户未登录或当前账户无法使用 PIN（政策限制）。

**解决**: 检查组织策略或联系管理员。

### PIN 验证失败

**原因**: 输入的 PIN 与存储的 PIN 不匹配。

**解决**:
- 确认输入的 PIN 无拼写错误。
- 若忘记 PIN，可使用主密码或生物识别解锁应用，然后重新设置 PIN。

### 重启后无法解锁

**原因**: 用户禁用了生物识别和 PIN，且未设置主密码。

**解决**:
- 在应用重启前，至少启用生物识别、PIN 或确保有主密码。
- 若遇到此状态，可能需要重新登录应用。

## 参考

- `desktop/src/auth/components/set-pin.component.ts` - PIN 设置对话框组件
- `desktop/src/app/accounts/settings.component.ts` - 设置页面 PIN 逻辑（第 479-734 行）
- `desktop/src/key-management/lock/services/desktop-lock-component.service.ts` - 锁屏解锁选项聚合
- `desktop/src/key-management/electron-key.service.ts` - 密钥存储与 PIN 协调
- `llmdoc/architecture/pin-lock-architecture.md` - PIN 锁定完整架构文档
