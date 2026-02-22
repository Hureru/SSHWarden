# Biometric Cross-Platform Architecture

## 1. Identity

- **What it is:** A two-generation biometric authentication system (v1 and v2) that provides platform-specific unlock and authentication capabilities with hardware-backed key derivation.
- **Purpose:** Enables users to unlock their Bitwarden vault and sign SSH operations using biometric credentials (face, fingerprint, voice) protected by OS-specific security models (Windows Hello, Linux Polkit, macOS stub).

## 2. Core Components

- `desktop/desktop_native/core/src/biometric_v2/mod.rs` (`BiometricTrait`, 8 methods): Platform-agnostic trait defining the biometric authentication contract using conditional compilation dispatch via `#[cfg_attr]`.
- `desktop/desktop_native/core/src/biometric_v2/windows.rs` (`BiometricLockSystem`, `windows_hello_authenticate`, `windows_hello_authenticate_with_crypto`): Windows Hello implementation with dual-path unlock (ephemeral UV via `UserConsentVerifier`, persistent signing via `KeyCredentialManager`).
- `desktop/desktop_native/core/src/biometric_v2/linux.rs` (`BiometricLockSystem`, `polkit_authenticate_bitwarden_policy`): Linux Polkit-based implementation with ephemeral-only key storage via `EncryptedMemoryStore`.
- `desktop/desktop_native/core/src/biometric_v2/unimplemented.rs` (`BiometricLockSystem`): macOS stub returning `unimplemented!()` for all trait methods.
- `desktop/desktop_native/core/src/biometric_v2/windows_focus.rs` (`focus_security_prompt`, `set_focus`, `restore_focus`): Window focusing utilities for Windows Hello security prompt reliability.
- `desktop/desktop_native/napi/src/biometrics_v2.rs` (`BiometricLockSystem` NAPI wrapper, `init_biometric_system()`): NAPI-RS bindings exposing 8 async methods to Node.js/Electron.
- `desktop/src/key-management/biometrics/main-biometrics.service.ts` (`MainBiometricsService`): Main process service instantiating platform-specific OS biometrics implementations and delegating operations.
- `desktop/src/key-management/biometrics/native-v2/os-biometrics-windows.service.ts` (`OsBiometricsServiceWindows`): Windows v2 TypeScript wrapper calling `biometrics_v2` NAPI module with persistent enrollment support.
- `desktop/src/key-management/biometrics/native-v2/os-biometrics-linux.service.ts` (`OsBiometricsServiceLinux` v2): Linux v2 TypeScript wrapper calling `biometrics_v2` NAPI module (ephemeral-only, replaces legacy v1 via feature flag).
- `desktop/src/key-management/biometrics/desktop.biometrics.service.ts` (`DesktopBiometricsService`): Abstract base class defining desktop-specific biometric operations (key management, setup, persistent enrollment).
- `desktop/src/platform/main/desktop-credential-storage-listener.ts` (`DesktopCredentialStorageListener`): Main process IPC handler blocking access to `Bitwarden_biometric` service credentials, enforcing isolation from browser extensions.

## 3. Execution Flow (LLM Retrieval Map)

### BiometricTrait Definition & Conditional Compilation

- **Step 1 - Trait Declaration:** `desktop/desktop_native/core/src/biometric_v2/mod.rs:14-37` defines 8 async methods: `authenticate()`, `authenticate_available()`, `enroll_persistent()`, `provide_key()`, `unlock()`, `unlock_available()`, `has_persistent()`, `unenroll()`.

- **Step 2 - Platform Dispatch:** `desktop/desktop_native/core/src/biometric_v2/mod.rs:3-7` uses `#[cfg_attr]` to conditionally compile:
  - Linux → `linux.rs`
  - macOS → `unimplemented.rs`
  - Windows → `windows.rs`
  Each module exports `BiometricLockSystem` struct with same name but different internals.

- **Step 3 - Re-export:** `desktop/desktop_native/core/src/biometric_v2/mod.rs:12` re-exports `pub use biometric_v2::BiometricLockSystem` making struct available at module root level.

### Windows v2 Implementation - Two Unlock Paths

**Ephemeral Path (Fast, UV-based):**
1. User calls `provide_key(user_id, key)` on normal vault unlock (e.g., via password or existing session)
2. Key stored in `DpapiSecretKVStore` (Windows DPAPI-protected secure memory via `CryptProtectMemory` with `CRYPTPROTECTMEMORY_SAME_PROCESS` flag)
3. On biometric unlock, `unlock(user_id, hwnd)` calls `windows_hello_authenticate(hwnd, message)`
4. Function uses WinRT `UserConsentVerifier::RequestVerificationForWindowAsync()` (face/fingerprint yes/no prompt)
5. If verified, key retrieved from `secure_memory` and returned to caller
6. Window focusing via background thread calling `focus_security_prompt()` every 500ms to repeatedly apply `set_focus()` (multi-step: disable timeout → attach thread → call focus APIs → restore timeout)

**Persistent Path (Slower, Crypto-backed):**
1. User calls `enroll_persistent(user_id, key)` to create recoverable biometric-protected storage
2. Generates random 16-byte challenge and calls `windows_hello_authenticate_with_crypto(challenge)`
3. WinRT `KeyCredentialManager::RequestCreateAsync(CREDENTIAL_NAME, FailIfExists)` creates Windows Hello signing credential (or `OpenAsync()` if exists)
4. Calls `credential.RequestSignAsync(challenge)` producing deterministic signature (based on hardware TPM/security processor)
5. Derives 32-byte symmetric key via `SHA256(signature)` using `sha2` crate
6. Encrypts vault key with `XChaCha20Poly1305` AEAD cipher with random 24-byte nonce
7. Serializes `WindowsHelloKeychainEntry {nonce, challenge, wrapped_key}` as JSON
8. Stores in Windows Credential Manager via `CredWriteW()` with service="BitwardenBiometricsV2", account=user_id

**Unlock from Persistent:**
1. `unlock(user_id, hwnd)` retrieves entry from keychain via `CredReadW()`
2. Extracts challenge, calls `windows_hello_authenticate_with_crypto(challenge)` again
3. Signs same challenge producing same signature (deterministically)
4. Derives same symmetric key via `SHA256(signature)`
5. Decrypts wrapped vault key via `XChaCha20Poly1305.decrypt(derived_key, nonce, ciphertext)`
6. Returns recovered key; also caches in ephemeral `secure_memory` for fast subsequent unlocks

### Linux v2 Implementation - Ephemeral-Only via Polkit

1. User calls `provide_key(user_id, key)` storing key in `Arc<Mutex<EncryptedMemoryStore<String>>>`
2. `EncryptedMemoryStore` wraps key in kernel-protected encrypted memory (via `memfd_secret` or equivalent)
3. On `authenticate(hwnd, message)` or `unlock(user_id, hwnd)`:
   - Calls `polkit_authenticate_bitwarden_policy()` which uses zbus D-Bus client
   - D-Bus call to `AuthorityProxy::check_authorization("com.bitwarden.Bitwarden.unlock", AllowUserInteraction)` prompts user
   - If authorized, retrieves key from encrypted memory store
4. `enroll_persistent()` is no-op (returns `Ok(())`)
5. `has_persistent()` always returns `false`
6. `polkit_is_bitwarden_policy_available()` enumerates available Polkit actions checking if unlock action present

### macOS v2 Implementation - Stub

- All `BiometricTrait` methods in `unimplemented.rs` call `unimplemented!()` at compile-time
- macOS support not yet implemented in v2 (v1 uses Electron `systemPreferences.promptTouchID()` fallback)

### NAPI Bridge Layer

1. **Module Registration:** `desktop/desktop_native/napi/src/lib.rs` declares `pub mod biometrics_v2;` for NAPI export
2. **Type Wrapping:** `desktop/desktop_native/napi/src/biometrics_v2.rs:25-36` wraps Rust `BiometricLockSystem` in NAPI struct
3. **Function Export:** Each method marked with `#[napi]` derive macro:
   - `init_biometric_system() -> BiometricLockSystem` (factory)
   - 8 methods: `authenticate(system, hwnd, message) -> Promise<bool>`, etc.
   - Errors converted via `map_err(|e| napi::Error::from_reason(e.to_string()))`
4. **Compilation:** NAPI-RS crate compiles to `cdylib` (.node native addon); `napi-build` generates `index.d.ts` TypeScript definitions
5. **Auto-Generated Types:** `desktop/desktop_native/napi/index.d.ts:117-130` declares `biometrics_v2` namespace with:
   - `BiometricLockSystem` opaque class
   - 8 async functions: `authenticate()`, `unlockAvailable()`, `enrollPersistent()`, etc.
   - `Buffer` parameter marshalling for window handles (hwnd) and key bytes

### TypeScript Layers (Main + Renderer)

**Main Process (Rust → TypeScript Bridge):**
1. `desktop/src/key-management/biometrics/main-biometrics.service.ts:213-221` instantiates `MainBiometricsService` in `main.ts`
2. Constructor selects platform implementation:
   - Windows → `WindowsBiometricsSystem` (from `native-v2/`)
   - Linux → `LinuxBiometricsSystem` (legacy v1) or switched to v2 via `enableLinuxV2Biometrics()`
   - macOS → stub or legacy impl
3. `MainBiometricsIPCListener` registered on "biometric" IPC channel routing 13 `BiometricAction` types

**Renderer Process (Browser Extension ↔ Native Messaging):**
1. `BiometricMessageHandlerService` (renderer) handles native messaging from browser extensions
2. Uses `ConnectedApps` ephemeral storage with RSA encryption handshake
3. Commands: `UnlockWithBiometricsForUser`, `AuthenticateWithBiometrics`, `GetBiometricsStatus`
4. Feature flag `FeatureFlag.LinuxBiometricsV2` enables v2 on Linux (checked during init)

**IPC Isolation:**
- `DesktopCredentialStorageListener` blocks IPC access to `Bitwarden_biometric` service credentials
- Prevents browser extensions from reading/writing biometric secrets
- All biometric credential operations isolated to main process and native modules

### v1 → v2 Migration Path

1. **Parallel Existence:** v1 (legacy) and v2 (new) coexist in same codebase
2. **Feature Flag Control:** `FeatureFlag.LinuxBiometricsV2` checked in `BiometricMessageHandlerService`
3. **Runtime Replacement:** Calling `MainBiometricsService.enableLinuxV2Biometrics()`:
   - Replaces `this.osBiometricsService` with `LinuxBiometricsSystem` (v2 native-v2 impl)
   - Sets `this.linuxV2BiometricsEnabled = true` (in-memory flag, persists until app restart)
4. **Subsequent Operations:** All biometric calls route to v2 implementation
5. **Query Method:** `isLinuxV2BiometricsEnabled()` allows renderer to check active version

## 4. Design Rationale

### Deterministic Key Derivation (Windows v2 Persistent)
Windows Hello signing of a fixed challenge produces the same signature each time, allowing key derivation without key material storage. This trade-off enables persistent encryption without persistent key storage—attack surface is Windows Hello prompt spoofing or keychain compromise.

### Dual-Path Unlock (Windows v2)
Ephemeral path (UV + DPAPI) requires app running but prevents keychain attacks. Persistent path (signing-based encryption) survives app restart but requires Polkit/Windows Hello authentication each unlock. Users choose appropriate path per use case.

### Polkit-Only Linux (v2)
Linux lacks native biometric hardware APIs; Polkit provides OS-level authentication abstraction supporting fingerprint readers via `fprintd` daemon. No persistent key storage because Polkit signatures are not deterministic.

### NAPI Boundary Enforcement
TypeScript services never directly handle key material; all crypto operations in Rust NAPI layer. `DesktopCredentialStorageListener` enforces service name filtering preventing extension access to biometric credentials via IPC.

### Window Focus Workaround (Windows)
Windows Hello signing requires focused window but WinRT provides no reliable API. Background thread continuously applies aggressive focus forcing (disable timeout, attach thread, multi-step focus calls) to work around OS limitations. Restoration gentle to avoid Electron freeze.

### Memory Protection Layers
- **Windows:** DPAPI in-process encryption + XChaCha20Poly1305 persistent encryption + `ZeroAlloc` global allocator
- **Linux:** Kernel-protected encrypted memory (`memfd_secret`) + `ZeroAlloc`
- **Encryption:** Random nonces per operation; no hardcoded keys; derived keys ephemeral
