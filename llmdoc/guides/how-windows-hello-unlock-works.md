# How Windows Hello Unlock Works

A step-by-step guide explaining how users enable Windows Hello biometric unlock and the two distinct unlock paths: ephemeral (session-only) vs persistent (cross-reboot).

## Part A: Enabling Windows Hello

### 1. User Navigates to Settings and Enables Biometric Unlock

**Location:** Settings page (`settings.component.ts`)

- User checks the "Unlock Windows Hello" checkbox in the security settings UI.
- Angular form binding: `form.value.biometric` toggles.
- Handler triggers: `updateBiometricHandler()` → calls `updateBiometric()`.

### 2. System Checks Prerequisites

**File:** `os-biometrics-windows.service.ts:34-35`

- Application calls `biometrics_v2.authenticateAvailable(system)` via NAPI.
- Rust code queries WinRT: `UserConsentVerifier::CheckAvailabilityAsync()`.
- Result: Returns `Available` or `DeviceBusy` → Windows Hello is supported on this device.
- If unavailable, error dialog shown to user; setup aborted.

### 3. User Confirms Permission

**File:** `settings.component.ts:676-687` (Windows special handling)

- User must approve Windows Hello prompts in a Windows Hello consent dialog.
- If user has no master password and no PIN set, application automatically calls `enrollPersistentBiometricIfNeeded()`.
- **This is critical:** Without persistent enrollment, user would be locked out after app restart (no ephemeral key in memory).

### 4. Key is Stored for Quick Access

**Flow:**
- On every successful login, `setBiometricProtectedUnlockKeyForUser(userId, key)` is called (Renderer → IPC → Main → NAPI).
- Rust stores key in DPAPI-protected secure memory (fast ephemeral path for current session).
- If persistent enrollment enabled, key also encrypted and stored in Windows Credential Manager (survives restart).

**Result:** Windows Hello is now enabled for this user.

---

## Part B: Ephemeral Unlock (Session-Only, First Unlock Path)

**When used:** After user logs in to app, before app is closed or vault is locked.

**Requirements:** Key must be stored in process memory via `provide_key()`.

### Flow

1. **User Locks Vault:** Clicks "Lock" button or app enters background.
   - Vault is locked, but application is still running.
   - Encrypted key held in DPAPI-protected memory in `DpapiSecretKVStore`.

2. **User Wants to Unlock:** Clicks "Unlock with Windows Hello" on lock screen.
   - IPC call: `ipc.keyManagement.biometric.unlockWithBiometricsForUser(userId)`.

3. **Main Process Routes to NAPI:** Calls `biometrics_v2.unlock(system, userId, hwnd)`.

4. **Rust Checks Ephemeral Path:** `BiometricLockSystem.unlock()` checks `secure_memory.has(userId)`.
   - **If true:** Key is in memory (ephemeral path).
   - **If false:** Key not in memory; fall through to persistent path (see Part C).

5. **Windows Hello UV Prompt:**
   - Calls `windows_hello_authenticate("Unlock your vault")`.
   - WinRT API: `UserConsentVerifier::RequestVerificationForWindowAsync()`.
   - User sees Windows Hello dialog (face/fingerprint).

6. **User Biometric Verification:**
   - User looks at camera (face) or touches fingerprint reader.
   - Windows Hello verifies biometric data against stored template.
   - Result: Approved → dialog returns `UserConsentVerificationResult::Verified`.

7. **Key Returned:** `secure_memory.get(userId)` retrieves decrypted key.

8. **Unlock Complete:** Vault is unlocked; user can access passwords.

**Characteristics:**
- **Speed:** Very fast (no crypto operations, simple yes/no prompt).
- **Limitations:** Requires app to be running; key held only in current session.
- **Security:** Ephemeral key protected by DPAPI (process-boundary encryption).

---

## Part C: Persistent Unlock (Cross-Reboot, Signing Path)

**When used:** User wants to unlock vault after app restart without re-entering master password.

**Requirements:** Persistent enrollment must be active (keys stored in Windows Credential Manager).

### Enrollment (One-Time Setup)

**When triggered:**
- User enables Windows Hello and has no master password + no PIN (auto-enrollment, line 676-687 in `settings.component.ts`).
- OR user manually selects "Save persistent unlock key" option (if UI exposed).

**Flow:**

1. **Generate Challenge:** Random 16-byte value unique to this enrollment.
   - Ensures each enrollment produces a unique Windows Hello key.

2. **Crypto Authentication:** Call `windows_hello_authenticate_with_crypto(&challenge)`.

3. **Window Focus Management:**
   - Spawn background thread calling `focus_security_prompt()` every 500ms.
   - Thread searches for "Credential Dialog Xaml Host" window and aggressively focuses it.
   - This ensures Windows Hello signing dialog receives input focus (face/fingerprint will not work without focus).

4. **Create or Open Windows Hello Key:**
   - `KeyCredentialManager::RequestCreateAsync(CREDENTIAL_NAME, FailIfExists)`.
   - If key already exists: `KeyCredentialManager::OpenAsync(CREDENTIAL_NAME)`.
   - Key is hardware-backed (stored in TPM or security processor).

5. **Sign Challenge:**
   - `credential.RequestSignAsync(CryptographicBuffer::CreateFromByteArray(&challenge))`.
   - User sees Windows Hello dialog; authenticates with biometric.
   - Signature generated (deterministic: same challenge → same signature).

6. **Derive Symmetric Key:**
   - `Sha256::digest(signature)` → 32-byte encryption key.
   - No key storage; key is ephemeral (derived on each unlock).

7. **Encrypt Vault Key with XChaCha20Poly1305:**
   - Generate random 24-byte nonce.
   - `encrypt(derived_key, vault_key)` → ciphertext.
   - Bundle: `{nonce, challenge, wrapped_key}` as JSON.

8. **Store in Windows Credential Manager:**
   - JSON serialized to string.
   - `CredWriteW(service="BitwardenBiometricsV2", account=userId, password=jsonString)`.
   - Stored securely in Windows Credential Manager (encrypted by Windows).

9. **Background Thread Stops:** Scope guard signals thread to stop focusing.

**Result:** Persistent key stored; user can now unlock after app restart.

---

### Unlock (Post-Reboot)

**Scenario:** User closes app or restarts computer; returns to app.

**Flow:**

1. **App Starts:** User on login screen; ephemeral `secure_memory` is empty (new process).

2. **User Selects Unlock with Windows Hello:** Clicks biometric unlock button.
   - IPC: `ipc.keyManagement.biometric.unlockWithBiometricsForUser(userId)`.

3. **Rust Checks Ephemeral Path:** `secure_memory.has(userId)` → **false** (empty new process).
   - Falls through to persistent path.

4. **Retrieve from Keychain:**
   - `CredReadW(service="BitwardenBiometricsV2", account=userId)`.
   - Result: JSON `{nonce, challenge, wrapped_key}` deserialized.

5. **Crypto Re-Authentication:**
   - Call `windows_hello_authenticate_with_crypto(&keychain_entry.challenge)`.
   - **Same focus thread:** Spawns background thread, repeats aggressive focus sequence.

6. **Open Existing Windows Hello Key:**
   - `KeyCredentialManager::OpenAsync(CREDENTIAL_NAME)`.
   - Opens TPM-backed key (same key from enrollment).

7. **Sign Challenge Again:**
   - `credential.RequestSignAsync(&challenge)` (same challenge as enrollment).
   - Signature is **deterministic** (same challenge, same key → same signature).
   - User authenticates with biometric.

8. **Re-Derive Same Key:**
   - `Sha256::digest(signature)` → **same 32-byte key** as enrollment.
   - No key storage or transmission.

9. **Decrypt Vault Key:**
   - `decrypt(derived_key, ciphertext, nonce)` → original vault key.
   - XChaCha20Poly1305 authentication tag verified; tampering detected if invalid.

10. **Ephemeral Cache:** `secure_memory.put(userId, &decrypted_key)`.
    - Key cached in DPAPI for faster subsequent unlocks in current session.

11. **Return Key:** Vault unlocked; user logged in.

**Characteristics:**
- **Persistence:** Survives app restarts and system reboots (key stored in Windows Credential Manager).
- **Slowness:** Slower than ephemeral (requires crypto operations and focus workarounds).
- **Security:** Key never stored in plaintext; encrypted with Windows Hello-derived key; challenge and nonce prevent replay attacks.

---

## Part D: Unlock Path Selection Logic

**Decision Tree in `BiometricLockSystem.unlock()`:**

```
if secure_memory.has(user_id) {
    // Fast ephemeral path
    windows_hello_authenticate(message)  // yes/no prompt
    return secure_memory.get(user_id)
} else {
    // Slow persistent path
    keychain_entry = get_keychain_entry(user_id)
    windows_hello_key = windows_hello_authenticate_with_crypto(&keychain_entry.challenge)
    decrypted_key = decrypt(windows_hello_key, ciphertext, nonce)
    secure_memory.put(user_id, decrypted_key)  // cache for next unlock
    return decrypted_key
}
```

**Key Decision Point:** Is key in `secure_memory`?
- **Yes:** Use UV path (faster, requires app running).
- **No:** Use signing path (slower, persistent across restarts).

---

## Part E: Disabling Windows Hello

**Flow:**

1. **User Unchecks "Unlock Windows Hello":**
   - Renderer: `ipc.keyManagement.biometric.deleteBiometricUnlockKeyForUser(userId)`.

2. **Main Process Removes Keys:**
   - `MainBiometricsService.deleteBiometricUnlockKeyForUser(userId)`.

3. **NAPI Call:** `biometrics_v2.unenroll(system, userId)`.

4. **Rust Cleanup:**
   - `secure_memory.remove(userId)` → removes ephemeral key from DPAPI store.
   - `delete_keychain_entry(userId)` → `CredDeleteW()` removes persistent entry from Windows Credential Manager.

5. **Result:** All Windows Hello keys removed for this user; biometric unlock no longer available.

---

## Verification Checklist

After completing these steps, verify the implementation:

1. **Ephemeral Path Test:**
   - [ ] Login to app.
   - [ ] Lock vault (without closing app).
   - [ ] Click "Unlock with Windows Hello".
   - [ ] Windows Hello dialog appears (face/fingerprint).
   - [ ] Vault unlocks immediately (no crypto latency).

2. **Persistent Path Test:**
   - [ ] Enable Windows Hello (no master password or PIN set).
   - [ ] Close app completely.
   - [ ] Reopen app; see login screen.
   - [ ] Click "Unlock with Windows Hello".
   - [ ] Windows Hello dialog appears; authentication slower than ephemeral.
   - [ ] Vault unlocks after biometric verification.

3. **Disable Test:**
   - [ ] Uncheck "Unlock Windows Hello" in settings.
   - [ ] Biometric unlock option no longer visible on login screen.
   - [ ] No residual keys in Windows Credential Manager (`Win + R` → `vault` command, Manage Credentials).

4. **Focus Management Verification:**
   - [ ] Windows Hello dialog appears in foreground during biometric operations.
   - [ ] Dialog can be interacted with (face/fingerprint input accepted).
   - [ ] After unlock, previous window (e.g., browser) regains focus without freezing.
