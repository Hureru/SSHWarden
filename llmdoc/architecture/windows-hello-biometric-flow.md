# Architecture of Windows Hello Biometric Flow

## 1. Identity

- **What it is:** End-to-end Windows Hello biometric authentication and persistent key management system, spanning Rust WinRT APIs, NAPI bindings, and TypeScript application layer.
- **Purpose:** Enable users to unlock vault keys using Windows Hello (face/fingerprint) authentication, with support for both ephemeral (session) and persistent (post-reboot) unlock paths.

## 2. Core Components

- `desktop/desktop_native/core/src/biometric_v2/mod.rs` (`BiometricTrait`): Platform-agnostic trait defining 8 async methods for biometric authentication and key management, dispatched via conditional compilation to platform-specific implementations.

- `desktop/desktop_native/core/src/biometric_v2/windows.rs` (`BiometricLockSystem`, `windows_hello_authenticate`, `windows_hello_authenticate_with_crypto`): Windows Hello implementation using WinRT APIs (UserConsentVerifier, KeyCredentialManager), DPAPI-protected ephemeral storage, and XChaCha20Poly1305 persistent encryption.

- `desktop/desktop_native/core/src/biometric_v2/windows_focus.rs` (`focus_security_prompt`, `set_focus`, `restore_focus`): Window focus management to ensure Windows Hello dialog receives input focus via aggressive Win32 API manipulation (SystemParametersInfoW, AttachThreadInput, SetForegroundWindow).

- `desktop/desktop_native/core/src/secure_memory/dpapi.rs` (`DpapiSecretKVStore`): Windows DPAPI-protected in-memory key-value store using CryptProtectMemory with CRYPTPROTECTMEMORY_SAME_PROCESS flag for process-boundary encryption.

- `desktop/desktop_native/core/src/password/windows.rs` (set_password, get_password, delete_password): Windows Credential Manager wrapper (CredWriteW, CredReadW, CredDeleteW) for persistent keychain storage.

- `desktop/desktop_native/napi/src/biometrics_v2.rs` (`BiometricLockSystem` NAPI struct, `init_biometric_system`): NAPI-RS bridge layer exposing 8 async methods to Node.js/Electron, with automatic type marshalling and error conversion.

- `desktop/src/key-management/biometrics/native-v2/os-biometrics-windows.service.ts` (`OsBiometricsServiceWindows`): TypeScript service wrapping NAPI biometrics_v2 module, integrating with Electron window handles and application key management.

- `desktop/src/key-management/biometrics/main-biometrics.service.ts` (`MainBiometricsService`): Main process service instantiating platform-specific OS biometrics services and managing lifecycle across Renderer process via IPC.

## 3. Execution Flow (LLM Retrieval Map)

### A. Ephemeral Unlock (Session-Only, First Unlock Path)

1. **Key Provision:** User logs in to vault, calls `biometricsService.setBiometricProtectedUnlockKeyForUser(userId, key)` from Renderer.
2. **IPC Routing:** `RendererBiometricsService` invokes `ipc.keyManagement.biometric.setBiometricProtectedUnlockKeyForUser()` → serializes key to Buffer.
3. **Main Process Dispatch:** `MainBiometricsIPCListener` receives `BiometricAction.SetKeyForUser` → calls `MainBiometricsService.setBiometricProtectedUnlockKeyForUser()`.
4. **Platform Delegation:** `MainBiometricsService` (Windows) delegates to `OsBiometricsServiceWindows.setBiometricKey()`.
5. **NAPI Call:** `OsBiometricsServiceWindows` calls `biometrics_v2.provideKey(system, userId, keyBuffer)` → serializes to NAPI Buffer.
6. **Rust Secure Storage:** `desktop_native::biometric_v2::windows::BiometricLockSystem.provide_key()` stores key in `secure_memory: DpapiSecretKVStore`.
7. **DPAPI Encryption:** `DpapiSecretKVStore.put()` encrypts key via Windows DPAPI (CryptProtectMemory) with CRYPTPROTECTMEMORY_SAME_PROCESS flag.
8. **Result:** Key held in encrypted process memory, inaccessible to other processes or SYSTEM.

**Unlock (Ephemeral Path):**
1. **User Requests Unlock:** `biometricsService.unlockWithBiometricsForUser(userId)` from Renderer.
2. **IPC to Main:** `ipc.keyManagement.biometric.unlockWithBiometricsForUser()` → `MainBiometricsIPCListener.handle()` → `MainBiometricsService.unlockWithBiometricsForUser()`.
3. **Platform Dispatch:** `OsBiometricsServiceWindows.getBiometricKey()` called.
4. **NAPI Unlock Call:** `biometrics_v2.unlock(system, userId, hwnd)` with native window handle.
5. **Ephemeral Check:** `BiometricLockSystem.unlock()` checks `secure_memory.has(userId)` → true (key was provided).
6. **Windows Hello UV Prompt:** Calls `windows_hello_authenticate(message)` → uses `UserConsentVerifier::RequestVerificationForWindowAsync()`.
7. **WinRT API Flow:** Safely cast to `IUserConsentVerifierInterop` → call interop method with foreground window handle.
8. **User Biometric:** Windows Hello dialog prompts face/fingerprint → returns `UserConsentVerificationResult::Verified`.
9. **Key Retrieval:** `secure_memory.get(userId)` retrieves DPAPI-decrypted key.
10. **Return to Renderer:** Key returned as Buffer via NAPI → reconstructed as `SymmetricCryptoKey` in `RendererBiometricsService`.

---

### B. Persistent Unlock (Cross-Reboot, Signing Path)

**Enrollment Flow:**
1. **Enroll Request:** User enables persistent biometric via settings → `biometricsService.enrollPersistent(userId, key)`.
2. **IPC Routing:** Renderer → Main IPC listener → `MainBiometricsService.enrollPersistent()`.
3. **NAPI Call:** `OsBiometricsServiceWindows.enrollPersistent()` → `biometrics_v2.enrollPersistent(system, userId, keyBuffer)`.
4. **Challenge Generation:** `BiometricLockSystem.enroll_persistent()` generates random 16-byte challenge (`rand::random()`).
5. **Crypto Authentication:** Calls `windows_hello_authenticate_with_crypto(&challenge)` to derive encryption key.
   - **Focus Thread:** Spawns background thread calling `focus_security_prompt()` every 500ms (locates "Credential Dialog Xaml Host" via `FindWindowA`).
   - **Aggressive Focus:** `set_focus()` temporarily disables foreground timeout via `SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT)`, attaches thread input, calls sequence: SetForegroundWindow → SetCapture → SetFocus → SetActiveWindow → EnableWindow → BringWindowToTop → SwitchToThisWindow, then detaches.
   - **Key Credential Creation:** Calls `KeyCredentialManager::RequestCreateAsync(CREDENTIAL_NAME, FailIfExists)` → if exists, opens with `OpenAsync()`.
   - **Challenge Signing:** `credential.RequestSignAsync(CryptographicBuffer::CreateFromByteArray(&challenge))` → awaits `IAsyncOperation<KeyCredentialSignResult>`.
   - **Signature Extraction:** Unsafe cast `IBuffer` via `IBufferByteAccess::Buffer()` to mutable bytes.
   - **Key Derivation:** `Sha256::digest(signature_value)` → 32-byte symmetric key.
6. **XChaCha20Poly1305 Encryption:**
   - Generate random 24-byte nonce (`rand::fill()`).
   - `cipher.encrypt(nonce, plaintext=vault_key)` → ciphertext.
7. **Keychain Entry Serialization:** Bundle `{nonce, challenge, wrapped_key}` as JSON struct `WindowsHelloKeychainEntry`.
8. **Windows Credential Manager Storage:** `set_keychain_entry()` → `password::set_password("BitwardenBiometricsV2", userId, jsonString)` → `CredWriteW()` API.
9. **Result:** Persistent key stored encrypted in Windows Credential Manager, recoverable only with Windows Hello signature.

**Unlock (Persistent Path, Post-Reboot):**
1. **Unlock Request:** `biometrics_v2.unlock(system, userId, hwnd)` called.
2. **Ephemeral Check:** `secure_memory.has(userId)` → false (no key in memory after reboot).
3. **Keychain Retrieval:** `get_keychain_entry(userId)` → `password::get_password()` → `CredReadW()` from Credential Manager.
4. **Deserialization:** JSON parsed to `WindowsHelloKeychainEntry` → extract nonce and challenge.
5. **Crypto Re-authentication:** Calls `windows_hello_authenticate_with_crypto(&keychain_entry.challenge)`.
   - **Same Focus Thread:** Spawns background thread, aggressive focus sequence (same as enrollment).
   - **Key Credential Open:** `KeyCredentialManager::OpenAsync(CREDENTIAL_NAME)` → opens existing TPM key.
   - **Challenge Re-signing:** `credential.RequestSignAsync(&challenge)` → signature deterministic (same challenge → same signature).
   - **Key Re-derivation:** `Sha256::digest(signature)` → same 32-byte key as enrollment.
6. **XChaCha20Poly1305 Decryption:** `cipher.decrypt(nonce, ciphertext)` → plaintext = original vault_key.
7. **Ephemeral Caching:** `secure_memory.put(userId, &decrypted_key)` → DPAPI protects key in memory for faster subsequent unlocks.
8. **Return Key:** Key returned as Buffer → reconstructed as `SymmetricCryptoKey` in Renderer.

---

### C. Window Focus Management Detail

**Problem:** Windows Hello signing API requires the prompt window to have input focus; without it, face/fingerprint authentication fails.

**Solution:** `windows_focus.rs` implements three operations:

- **`focus_security_prompt()`** (called every 500ms by background thread):
  - Locates "Credential Dialog Xaml Host" window via `FindWindowA(s!("Credential Dialog Xaml Host"), None)`.
  - Calls `set_focus(hwnd)` on found window.

- **`set_focus(hwnd)`** (aggressive forcing):
  1. Read current foreground lock timeout via `SystemParametersInfoW(SPI_GETFOREGROUNDLOCKTIMEOUT)`.
  2. Temporarily set timeout to 0 via `SystemParametersInfoW(SPI_SETFOREGROUNDLOCKTIMEOUT, 0)`.
  3. Get current thread ID and foreground thread ID via `GetCurrentThreadId()` and `GetWindowThreadProcessId()`.
  4. Attach current thread to foreground thread: `AttachThreadInput(current, foreground, true)`.
  5. Call sequence (all on target window):
     - `SetForegroundWindow(hwnd)`
     - `SetCapture(hwnd)`
     - `SetFocus(Some(hwnd))`
     - `SetActiveWindow(hwnd)`
     - `EnableWindow(hwnd, true)`
     - `BringWindowToTop(hwnd)`
     - `SwitchToThisWindow(hwnd, true)`
  6. Detach thread: `AttachThreadInput(current, foreground, false)`.
  7. Restore timeout via scopeguard.

- **`restore_focus(hwnd)`** (gentle restoration):
  - Calls only `SetForegroundWindow()` and `SetFocus()` to restore previous window (e.g., browser) without aggressive hacks.

---

### D. NAPI Bridge Layer

**NAPI Module Structure:**
- `desktop_native/napi/src/lib.rs` declares `pub mod biometrics_v2;`.
- `biometrics_v2.rs` wraps Rust `desktop_core::biometric_v2::BiometricLockSystem` via `#[napi]` macro.
- Each method marked with `#[napi]` is auto-compiled to JavaScript binding via NAPI-RS build tool.

**NAPI Method Signatures (Rust → TypeScript):**
- `init_biometric_system() -> BiometricLockSystem` (factory).
- `authenticate(system, hwnd: Buffer, message: String) -> Promise<bool>`.
- `authenticate_available(system) -> Promise<bool>`.
- `enroll_persistent(system, user_id: String, key: Buffer) -> Promise<()>`.
- `provide_key(system, user_id: String, key: Buffer) -> Promise<()>`.
- `unlock(system, user_id: String, hwnd: Buffer) -> Promise<Buffer>`.
- `unlock_available(system, user_id: String) -> Promise<bool>`.
- `has_persistent(system, user_id: String) -> Promise<bool>`.
- `unenroll(system, user_id: String) -> Promise<()>`.

**Type Marshalling:**
- `Buffer` parameters marshalled via `napi::bindgen_prelude::Buffer` ↔ Rust `&[u8]`.
- Errors converted via `map_err(|e| napi::Error::from_reason(e.to_string()))`.
- TypeScript definitions auto-generated in `index.d.ts` with camelCase naming.

---

### E. TypeScript Application Integration

**Full Request-Response Cycle:**

```
Renderer Process:
  settings.component.ts (updateBiometric)
  ↓
  RendererBiometricsService (ipc.keyManagement.biometric.setBiometricProtectedUnlockKeyForUser)
  ↓
  ipcRenderer.invoke("biometric", BiometricMessage{action, userId, key})

Main Process:
  MainBiometricsIPCListener.handle() receives message
  ↓
  Routes to MainBiometricsService.setBiometricProtectedUnlockKeyForUser()
  ↓
  OsBiometricsServiceWindows.setBiometricKey()
  ↓
  biometrics_v2.provideKey(system, userId, Buffer)

Rust (NAPI):
  BiometricLockSystem.provide_key() serialized as NAPI call
  ↓
  BiometricLockSystem.provide_key() stores in DpapiSecretKVStore
  ↓
  Returns Promise<()> back through NAPI

Main → Renderer:
  Returns response to ipcRenderer.invoke() call
```

---

## 4. Design Rationale

### Dual-Path Security Model

**Why two unlock paths?**
- **Ephemeral (UV):** Fast unlock for users still running the app. Requires user to be logged in first to provide key. Uses simple yes/no prompt (better focus behavior).
- **Persistent (Signing):** Survives app restart. Requires crypto authentication. Slower but enables cross-reboot vault access without re-entry of master password.

### Deterministic Key Derivation

**Why hash Windows Hello signature?**
- Windows Hello signing is deterministic (same challenge → same signature) if the TPM/security processor hasn't changed.
- SHA256 hash of signature provides stable 32-byte encryption key without storing the signature itself.
- Attack surface: Attacker must create fake Windows Hello prompt or compromise Windows Credential Manager (user-space).

### DPAPI for Ephemeral Keys

**Why DPAPI + process boundary?**
- Windows DPAPI (`CryptProtectMemory`) encrypts data at process boundary, inaccessible to other processes unless they compromise SYSTEM or kernel.
- Ephemeral keys held in memory even when vault is locked (UX benefit: instant unlock after first auth).
- Global allocator `ZeroAlloc` zeros freed memory to prevent key residue.

### XChaCha20Poly1305 for Persistent Keys

**Why not use DPAPI for persistent keys?**
- DPAPI is process-specific; encrypted data cannot be retrieved after process restart.
- Persistent keys require storage outside process memory → Windows Credential Manager.
- XChaCha20Poly1305 provides authenticated encryption with random nonce per enrollment (prevents replay attacks).

### Window Focus as Engineering Necessity

**Why aggressive focus manipulation?**
- Windows Hello signing API has inconsistent focus behavior when called from background windows.
- No official Windows API provides reliable prompting from unfocused application.
- Background thread strategy mitigates race conditions between focus request and authentication prompt.
- Gentle focus restoration prevents freezing of Electron main window.
