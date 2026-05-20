# Architecture of PIN Encryption in SSHWarden

## 1. Identity

- **What it is:** SSHWarden 的 PIN 便捷解锁子系统，使用 Argon2id 从 PIN 派生对称密钥对密钥缓存进行加解密，并持久化到 vault.enc 文件。
- **Purpose:** 允许用户通过短 PIN 快速解锁已锁定的密码库，无需重新输入 Bitwarden 主密码或联网重新同步。支持跨守护进程重启的持久化解锁。

## 2. Core Components

- `crates/sshwarden-api/src/crypto.rs` (`derive_pin_key`, `pin_encrypt`, `pin_decrypt`, `encrypt_enc_string`): PIN 加解密核心函数。`derive_pin_key` 的 key_material 使用 `Zeroizing` 包装，scope 结束自动擦零。
- `crates/sshwarden-config/src/vault.rs` (`VaultFile`): vault.enc 持久化文件结构（version, pin_encrypted, hello_challenge, email, server_url），存放于 exe 同目录，支持 load/save/delete。
- `src/main.rs` (`handle_control_command` -- `SetPin`/`UnlockPin` 分支): PIN 设置和 PIN 解锁的业务逻辑。参见 `src/main.rs:837-941` (SetPin), `src/main.rs:689-720` (UnlockPin).

## 3. Execution Flow (LLM Retrieval Map)

### 3.1 PIN 设置流程 (SetPin)

- **1. CLI 触发:** `sshwarden set-pin` 命令提示输入 PIN（>= 4 字符），两次确认后发送 `set-pin:{pin}` IPC 命令. 参见 `src/main.rs:203-217`.
- **2. 序列化密钥:** 主循环将 `cached_key_tuples` (Vec<(String, String, String)>) 序列化为 JSON. 参见 `src/main.rs:852-860`.
- **3. PIN 加密:** 调用 `sshwarden_api::crypto::pin_encrypt(&keys_json, &pin)`. 参见 `src/main.rs:862`.
- **4. Argon2id 派生:** `derive_pin_key(pin)` 使用 Argon2id（64 MiB memory, 3 iterations, parallelism=1）从 PIN 派生 64 字节密钥材料（`Zeroizing` 包装），拆分为 32 字节 enc_key + 32 字节 mac_key. 参见 `crates/sshwarden-api/src/crypto.rs`.
- **5. AES-256-CBC 加密:** `encrypt_enc_string()` 生成随机 16 字节 IV，AES-256-CBC + PKCS7 加密，HMAC-SHA256 签名(IV+密文)，输出 `2.{iv}|{data}|{mac}` 格式.
- **6. 双重存储:** 加密字符串同时存入内存 `pin_encrypted_keys` 和磁盘 vault.enc 文件. 参见 `src/main.rs:865-931`.
- **7. Hello 签名路径注册（可选）:** 若 Windows Hello 可用，生成 16 字节随机 challenge，用 KeyCredentialManager 签名 challenge 派生密钥加密密钥缓存，存入 Credential Manager，challenge 写入 vault.enc. 参见 `src/main.rs:880-920`.

### 3.2 PIN 解锁流程 (UnlockPin / PIN 对话框)

PIN 解锁有两种入口，但验证逻辑统一通过 `pin_decrypt()`:

**CLI 入口 (unlock --pin):**
- **1. CLI 触发:** `sshwarden unlock --pin` 提示输入 PIN，发送 `unlock-pin:{pin}` IPC 命令. 参见 `src/main.rs:137-140`.
- **2. 读取加密数据:** 调用 `get_pin_encrypted_data()` 优先从内存 `pin_encrypted_keys` 读取，若为空则从 `vault_file_data` 读取. 参见 `src/main.rs:1162-1174`.
- **3. PIN 解密:** 调用 `pin_decrypt(&enc_data, &pin)`. HMAC 验证 + AES 解密.
- **4. 重载密钥:** 调用 `finish_unlock_with_json()` 解析 JSON、更新 key_names、加载到 Agent、清除锁定标志.

**PIN 对话框入口 (validator 重试模式):**
- **1. 触发:** Hello 签名路径失败后的降级（3 处调用点）。调用 `get_pin_encrypted_data()` 读取加密数据.
- **2. 构造 validator:** `make_pin_validator(enc_data)` 返回 `(validator, decrypted_cache)`。validator 闭包内部调用 `pin_decrypt()` 验证 PIN. 参见 `src/main.rs:1180-1202`.
- **3. 对话框内验证:** `request_pin_dialog(tx, validator)` 发送到 Slint 主线程。对话框在后台线程调用 validator，失败时显示错误提示并允许重试，成功时将解密结果缓存到 `decrypted_cache`.
- **4. 取回结果:** 调用方从 `decrypted_cache.lock().unwrap().take().unwrap()` 取回已缓存的解密 JSON，避免重复执行 Argon2id KDF.
- **5. 重载密钥:** 调用 `finish_unlock_with_json()` 解析 JSON、加载密钥.

## 4. Design Rationale

- **Argon2id 固定 salt:** 使用 `SHA256("sshwarden-pin-key-derivation")` 作为固定 salt。PIN 仅用于便捷解锁（非主要安全机制），固定 salt 可接受。
- **双重存储:** `pin_encrypted_keys` 存在于内存中用于快速访问，同时持久化到 vault.enc 磁盘文件（位于 exe 同目录），守护进程重启后仍可通过 PIN 解锁。
- **vault.enc 启动检测:** `run_foreground()` 启动时检测 vault.enc 存在，若存在则跳过主密码提示，进入锁定状态等待 PIN/Hello/Password 解锁。参见 `src/main.rs:328-357`.
- **type 2 EncString:** 使用与 Bitwarden 兼容的 `2.{iv}|{data}|{mac}` 加密格式，复用现有解密基础设施。
- **HMAC-then-decrypt:** 先验证 HMAC 再解密，错误 PIN 在 HMAC 阶段即失败，避免 padding oracle 攻击。
