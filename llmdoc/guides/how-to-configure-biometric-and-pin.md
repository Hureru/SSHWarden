# 如何配置生物识别和 PIN 解锁

## 用户在设置页面启用/禁用 Windows Hello 的完整 UI 流程

### 启用 Windows Hello

1. **打开设置页面**：在应用菜单中选择"设置"。
2. **进入安全设置区域**：导航到"Vault（保险库）"部分的"安全设置"。
3. **勾选"解锁 Windows Hello"复选框**：在 settings.component.html 第 87-97 行所示的"解锁 Windows Hello"复选框上点击。
4. **系统验证硬件可用性**：
   - 系统自动检查 Windows Hello 是否在此设备上可用。
   - 若不可用，会弹出"需要手动设置"警告对话框，指向官方文档链接。
5. **配置推荐设置**（Windows 专有）：
   - 系统自动禁用"自动提示 Windows Hello"（autoPromptBiometrics = false）。
   - 若用户无主密码且无 PIN，系统会自动创建持久化生物识别密钥，允许应用重启时直接使用生物识别解锁。
   - 若用户有主密码或 PIN，系统会显示"重启时需要主密码/PIN"复选框（默认勾选）。
6. **验证生物识别可用性**：系统尝试存储用户的加密密钥到生物识别系统。若失败，复选框自动取消勾选并显示错误信息。
7. **流程完成**：复选框保持勾选状态，表示 Windows Hello 已启用。

### 禁用 Windows Hello

1. **打开设置页面**：同上。
2. **进入安全设置区域**：同上。
3. **取消勾选"解锁 Windows Hello"复选框**：在复选框上点击以禁用。
4. **系统清理**：
   - 系统删除存储的生物识别解锁密钥。
   - 密钥刷新以移除生物识别保护。
5. **特殊处理（Windows 平台）**：
   - 若用户已启用"重启时需要主密码/PIN"、已启用 Windows Hello、但无主密码，系统会自动创建持久化生物识别密钥（防止用户被锁定）。
6. **流程完成**：复选框变为未勾选状态。

**相关源代码** `desktop/src/app/accounts/settings.component.ts:633-703`

---

## 用户在设置页面启用/禁用 PIN 的完整 UI 流程

### 启用 PIN

1. **打开设置页面**：同上。
2. **确认 PIN 功能可用**：
   - 系统检查 `RemoveUnlockWithPin` 组织策略。
   - 若策略禁用了 PIN，复选框将完全隐藏。
3. **勾选"解锁 PIN"复选框**：在 settings.component.html 第 79-86 行所示的复选框上点击。
4. **打开 PIN 设置对话框**：
   - SetPinComponent 通过 DialogService 打开。
   - 用户输入 PIN（需验证确认）。
   - 可选配置"重启时需要主密码"选项。
5. **PIN 保存**：
   - 对话框返回布尔值表示是否成功设置。
   - 若成功，`userHasPinSet` 标志更新为 true，复选框保持勾选。
6. **流程完成**：PIN 已启用，用户可在锁屏时使用 PIN 解锁。

**相关源代码** `desktop/src/app/accounts/settings.component.ts:604-614` 和 `desktop/src/auth/components/set-pin.component.ts`

### 禁用 PIN

1. **打开设置页面**：同上。
2. **取消勾选"解锁 PIN"复选框**：在复选框上点击以禁用。
3. **系统清理**：
   - 调用 `pinService.unsetPin(userId)` 移除用户的 PIN 数据。
4. **Windows 平台特殊处理**：
   - 若用户已启用生物识别、要求"重启时需要主密码/PIN"、但无主密码，系统自动创建持久化生物识别密钥（防止无法解锁）。
5. **流程完成**：复选框变为未勾选状态，PIN 不再可用。

**相关源代码** `desktop/src/app/accounts/settings.component.ts:615-629`

---

## "重启时需要主密码/PIN" 选项的交互逻辑

### 显示条件

此选项仅在以下条件均满足时显示（settings.component.html:98-121）：
- 生物识别已启用 (`form.value.biometric`)
- 运行在 Windows 平台 (`isWindows`)
- 用户有主密码或已设置 PIN (`userHasMasterPassword || (form.value.pin && userHasPinSet)`)

### 启用此选项

**用户操作**：在"重启时需要主密码/PIN"复选框上勾选。

**系统行为**（settings.component.ts:714-719）：
1. 获取用户的主密钥 (userKey)。
2. 删除现有的持久化生物识别密钥 (`deleteBiometricUnlockKeyForUser`)。
3. 存储标准生物识别保护的密钥 (`setBiometricProtectedUnlockKeyForUser`)。
4. **结果**：应用重启时，用户必须先输入主密码或 PIN，然后才能使用生物识别解锁。

### 禁用此选项

**用户操作**：在"重启时需要主密码/PIN"复选框上取消勾选。

**系统行为**（settings.component.ts:720-723）：
1. 检查是否已存在持久化生物识别密钥。
2. 若不存在，调用 `enrollPersistentBiometricIfNeeded()` 创建持久化生物识别模板。
3. **结果**：应用重启时，用户可直接使用生物识别解锁，无需主密码或 PIN。

### 动态标签更新

HTML 标签会根据 PIN 是否启用动态变化（settings.component.html:114-118）：
- 若 PIN 已启用：显示"需要主密码或 PIN"。
- 若 PIN 已禁用：显示"需要主密码"。

**相关源代码** `desktop/src/app/accounts/settings.component.ts:705-724` 和 `settings.component.html:98-121`

---

## 持久化生物识别自动注册的触发条件

持久化生物识别注册（仅 Windows）在以下场景自动触发：

### 场景 1：启用生物识别且用户无主密码/PIN（settings.component.ts:682-684）

**触发条件**：
- 用户在 Windows 平台上启用生物识别。
- 用户没有主密码 (`!userHasMasterPassword`)。
- 用户没有设置 PIN (`!userHasPinSet`)。

**自动行为**：
- 系统自动调用 `enrollPersistentBiometricIfNeeded()`。
- 创建持久化生物识别模板，允许应用重启时直接解锁。
- `requireMasterPasswordOnAppRestart` 复选框自动设置为 false。

### 场景 2：禁用"重启时需要主密码/PIN"选项（settings.component.ts:720-723）

**触发条件**：
- 用户取消勾选"重启时需要主密码/PIN"复选框。

**自动行为**：
- 系统调用 `enrollPersistentBiometricIfNeeded()`。
- 检查是否已有持久化密钥，若无则创建。

### 场景 3：禁用 PIN 但用户处于危险状态（settings.component.ts:619-627）

**触发条件**：
- 用户在 Windows 平台上。
- 用户已启用生物识别。
- "重启时需要主密码/PIN"已启用。
- 用户没有主密码 (`!userHasMasterPassword`)。

**自动行为**：
- 系统自动调用 `enrollPersistentBiometricIfNeeded()`。
- 防止用户因移除 PIN 而陷入无法解锁状态。

**相关源代码** `desktop/src/app/accounts/settings.component.ts:726-734`

---

## 验证配置是否成功

1. **生物识别状态验证**：
   - 在设置页面检查"解锁 Windows Hello"复选框是否勾选。
   - 若成功启用，复选框应保持勾选状态。

2. **PIN 状态验证**：
   - 在设置页面检查"解锁 PIN"复选框是否勾选。
   - 若成功启用，复选框应保持勾选状态。

3. **应用重启测试**：
   - 关闭并重新启动应用。
   - 根据配置选项，验证是否要求主密码/PIN 或直接允许生物识别解锁。

4. **锁屏测试**（若配置了生物识别或 PIN）：
   - 使用 Vault → Lock 或超时使 Vault 进入锁定状态。
   - 尝试使用生物识别或 PIN 解锁。
   - 验证解锁是否成功。
