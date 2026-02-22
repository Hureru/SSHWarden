# Biometric Platform Comparison

## 1. Core Summary

The biometric subsystem provides three platform-specific implementations (Windows v2, Linux v1/v2, macOS stub) with fundamentally different capabilities and security models. Windows v2 supports persistent biometric-protected key storage and dual-path unlock via Windows Hello. Linux offers ephemeral keys with Polkit authentication (v1 uses hybrid split-key encryption; v2 uses native encrypted memory). macOS is unimplemented stub. All platforms expose identical trait interface but implement distinct unlock flows reflecting OS-level biometric APIs.

## 2. Source of Truth

### Primary Code

- **Trait Definition:** `desktop/desktop_native/core/src/biometric_v2/mod.rs:14-37` - 8 async methods defining platform-agnostic contract (authenticate, enroll_persistent, provide_key, unlock, etc.)
- **Windows Implementation:** `desktop/desktop_native/core/src/biometric_v2/windows.rs` - Windows Hello UV + crypto paths, DPAPI secure memory, keychain persistence
- **Linux Implementation:** `desktop/desktop_native/core/src/biometric_v2/linux.rs` - Polkit ephemeral auth, encrypted memory store
- **macOS Implementation:** `desktop/desktop_native/core/src/biometric_v2/unimplemented.rs` - Stub returning `unimplemented!()`
- **Conditional Compilation:** `desktop/desktop_native/core/src/biometric_v2/mod.rs:3-7` - `#[cfg_attr]` platform dispatch

### NAPI Bridge

- **Bindings:** `desktop/desktop_native/napi/src/biometrics_v2.rs` - NAPI-RS wrapper exposing 8 async methods to Node.js
- **TypeScript Definitions:** `desktop/desktop_native/napi/index.d.ts:117-130` - Auto-generated `biometrics_v2` namespace

### TypeScript Services

- **Main Process:** `desktop/src/key-management/biometrics/main-biometrics.service.ts` - Platform selector instantiating OS services
- **Windows v2 Service:** `desktop/src/key-management/biometrics/native-v2/os-biometrics-windows.service.ts` - Persistent enrollment support
- **Linux v2 Service:** `desktop/src/key-management/biometrics/native-v2/os-biometrics-linux.service.ts` - Ephemeral-only wrapper
- **Legacy Linux v1:** `desktop/src/key-management/biometrics/os-biometrics-linux.service.ts` - Hybrid split-key model

### Credential Storage Isolation

- **IPC Handler:** `desktop/src/platform/main/desktop-credential-storage-listener.ts` - Blocks `Bitwarden_biometric` service access via IPC

### Related Architecture

- `/llmdoc/architecture/ssh-agent-authorization-flow.md` - How vault lock gates biometric unlock operations
- `/llmdoc/architecture/ssh-agent-key-management.md` - Key storage and signing flow (integration point)

---

## Platform Capability Comparison Matrix

| Capability | Windows v2 | Linux v2 | Linux v1 | macOS v2 |
|---|---|---|---|---|
| **Authentication Method** | Windows Hello (face/fingerprint) + UserConsentVerifier | Polkit D-Bus auth | Polkit D-Bus auth | Unimplemented |
| **Ephemeral Key Storage** | DPAPI-protected memory | Encrypted memory store | Encrypted memory store | Unimplemented |
| **Persistent Enrollment** | ✓ (XChaCha20Poly1305 encrypted, Credential Manager) | ✗ (no-op) | ✗ (no-op) | Unimplemented |
| **Key Derivation** | Deterministic Windows Hello signing → SHA256 | Random challenge → SHA256 | Random challenge → SHA256 | Unimplemented |
| **Persistent Unlock** | ✓ (re-sign challenge, decrypt wrapped key) | ✗ (ephemeral only) | ✗ (ephemeral only) | Unimplemented |
| **Keychain Backend** | Windows Credential Manager (`BitwardenBiometricsV2` service) | None (ephemeral) | None (ephemeral) | Unimplemented |
| **App Restart Survival** | ✓ (persistent path) | ✗ | ✗ | Unimplemented |
| **Hardware Requirement** | TPM 2.0 or security processor (optional, fallback to software) | Fingerprint reader + fprintd daemon | Fingerprint reader + fprintd daemon | Unimplemented |
| **Unlock Prompt Type** | Face/fingerprint (face/touch ID via `RequestVerificationForWindowAsync`) | Polkit password/biometric dialog | Polkit password/biometric dialog | Unimplemented |
| **Window Focusing** | Required (background thread every 500ms) | Not applicable | Not applicable | Unimplemented |
| **Memory Protection** | DPAPI (`CryptProtectMemory` SAME_PROCESS) | Kernel encrypted memory (`memfd_secret`) | Kernel encrypted memory | Unimplemented |

---

## API Method Behavior by Platform

| Method | Windows v2 | Linux v2 | Linux v1 | macOS v2 |
|---|---|---|---|---|
| **authenticate(hwnd, message)** | `UserConsentVerifier::RequestVerificationForWindowAsync()` (yes/no prompt) | `AuthorityProxy::check_authorization()` Polkit prompt | N/A (v1) | `unimplemented!()` |
| **authenticate_available()** | Checks if Windows Hello available (always true on modern Windows) | `enumerate_actions()` checks for `com.bitwarden.Bitwarden.unlock` | N/A | `unimplemented!()` |
| **enroll_persistent(user_id, key)** | Sign challenge with `KeyCredentialManager`, derive key via SHA256, encrypt key with XChaCha20Poly1305, store to keychain | `Ok(())` (no-op) | `Ok(())` (no-op) | `unimplemented!()` |
| **provide_key(user_id, key)** | Store in `DpapiSecretKVStore` (DPAPI-protected) | Store in `Arc<Mutex<EncryptedMemoryStore>>` | N/A | `unimplemented!()` |
| **unlock(user_id, hwnd)** | If ephemeral key cached, return immediately. Otherwise: retrieve from keychain, call `windows_hello_authenticate_with_crypto()`, decrypt wrapped key | Call `polkit_authenticate_bitwarden_policy()`, retrieve from encrypted memory | N/A | `unimplemented!()` |
| **unlock_available(user_id)** | `has_persistent(user_id) \|\| has_ephemeral_key(user_id) && authenticate_available()` | `has_ephemeral_key(user_id) && authenticate_available()` | N/A | `unimplemented!()` |
| **has_persistent(user_id)** | Query Windows Credential Manager for entry | `false` (always) | `false` (always) | `unimplemented!()` |
| **unenroll(user_id)** | Delete from Credential Manager + clear ephemeral memory | Clear encrypted memory store | N/A | `unimplemented!()` |

---

## v1 vs v2 API Comparison (Rust Trait Level)

| Aspect | v1 (`biometric::BiometricTrait`) | v2 (`biometric_v2::BiometricTrait`) |
|---|---|---|
| **Trait Methods** | `prompt()`, `available()`, `derive_key_material()`, `set_biometric_secret()`, `get_biometric_secret()` (5 methods) | `authenticate()`, `authenticate_available()`, `enroll_persistent()`, `provide_key()`, `unlock()`, `unlock_available()`, `has_persistent()`, `unenroll()` (8 methods) |
| **State Management** | Stateless (functions only) | Stateful (BiometricLockSystem struct holds secure memory) |
| **Key Storage Model** | Hybrid split-key (OS part + client part, SHA256 combined), AES-256-CBC encryption | Native per-platform (DPAPI ephemeral + persistent, Polkit ephemeral) |
| **Persistent Storage** | Via system keychain (Linux: system password manager) | Platform-specific (Windows: Credential Manager, Linux: none) |
| **Cryptographic Backing** | AES-256-CBC with derived key | Windows: XChaCha20Poly1305 with Windows Hello signature-derived key; Linux: kernel encryption |
| **IV/Challenge** | Hybrid encryption uses client-provided IV + OS key part | Windows: unique 16-byte challenge per enrollment; Linux: challenge optional |
| **Platforms** | Linux ✓, Windows unimplemented, macOS unimplemented | Windows ✓, Linux ✓, macOS stub |
| **Primary Use Case** | Legacy Linux v1 (hybrid encryption) | Windows Hello integration + Linux Polkit modernization |

---

## Persistent vs Ephemeral Key Storage Matrix

| Storage Type | Windows v2 | Linux v2 | Linux v1 | Characteristics |
|---|---|---|---|---|
| **Ephemeral (Session)** | DPAPI-protected heap memory (`DpapiSecretKVStore`) | Kernel encrypted memory (`EncryptedMemoryStore`) | System keychain (encrypted) | Lost on app restart; faster access; no persistent enrollment |
| **Persistent (Durable)** | Windows Credential Manager (encrypted with Windows Hello signature-derived key) | None | System keychain (v1 only stores encrypted secrets) | Survives app restart/reboot; requires biometric auth per access; slower initial unlock |
| **Access Pattern** | Ephemeral: O(1) hash lookup. Persistent: O(1) keychain query + XChaCha20Poly1305 decrypt | Ephemeral: O(1) hash lookup. Persistent: N/A | System keychain query (depends on backend) | Ephemeral always faster; persistent requires crypto ops |
| **Isolation** | Only accessible within app process (DPAPI + process ID) | Only accessible within app process (kernel) | System-wide (keychain acts as isolator) | Ephemeral isolated by process; persistent isolated by DPAPI/kernel |
| **Encrypt/Decrypt** | Persistent: XChaCha20Poly1305 with random 24-byte nonce + deterministic Windows Hello signature key | None (ephemeral only) | AES-256-CBC with hybrid-derived key | Different ciphers reflect platform capabilities |

---

## Conditional Compilation & Feature Flag Control

| Control Mechanism | Scope | Effect |
|---|---|---|
| **Rust `#[cfg_attr]` Compile-Time** | `mod.rs:3-7` platform selection | Entire platform module (linux.rs vs windows.rs vs unimplemented.rs) compiled in or out at build time |
| **TypeScript Feature Flag Runtime** | `FeatureFlag.LinuxBiometricsV2` in renderer | At runtime, `MainBiometricsService.enableLinuxV2Biometrics()` replaces legacy `OsBiometricsServiceLinux` (v1) with new `LinuxBiometricsSystem` (v2) |
| **In-Memory State** | `MainBiometricsService.linuxV2BiometricsEnabled` | Boolean flag persists only for current process lifetime; survives account switch; lost on app restart |
| **Dispatch Layer** | Main process constructor | `WindowsBiometricsSystem` (Windows), `OsBiometricsServiceLinux` or v2 (Linux), macOS impl (macOS) |

---

## Security Boundaries

| Boundary | Enforcement | Violation Impact |
|---|---|---|
| **IPC Isolation** | `DesktopCredentialStorageListener` blocks `Bitwarden_biometric` service access | Browser extensions cannot read/write biometric secrets |
| **Memory Protection** | DPAPI (Windows) + kernel encryption (Linux) + `ZeroAlloc` global allocator | Freed memory immediately zeroed; core dumps disabled; process hardening via `PR_SET_DUMPABLE` |
| **Keychain Persistence** | Windows Hello signature determinism ensures only authorized user can derive decryption key | Keychain entry useless without Windows Hello prompt; tampering detected via AEAD failure |
| **Cross-Platform Key Portability** | None (by design) | Keys encrypted with platform-specific methods cannot be ported (e.g., Windows keychain entry invalid on Linux) |

