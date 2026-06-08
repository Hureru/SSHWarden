# Multi-device shared storage with device-local runtime state

## Status

Accepted

## Context

Some Windows users keep a portable SSHWarden installation under a cloud-synced directory such as OneDrive and use it from multiple machines. The Bitwarden vault remains the source of truth for SSH keys, but users may want the local Bitwarden projection (`local-key-cache.json`), host bindings, and public selector files to be shared across those machines so every device sees the same cached key identities and OpenSSH host routing rules.

The previous portable layout stored all SSHWarden files in one directory. That causes conflicts when the same directory is synced across devices: `sshwarden.pid`, logs, runtime sockets, Bitwarden session files, and platform-native unlock slots are device-local state and must not be overwritten by another device. At the same time, `bindings.json` and `keys/` are safe and useful to share, and a shared `local-key-cache.json` is acceptable when the user intentionally uses the same PIN across devices.

Windows OneDrive paths may differ only by username, for example:

```text
C:\Users\zheng\OneDrive\Program\SSHWarden
C:\Users\Administrator\OneDrive\Program\SSHWarden
```

A shared OpenSSH snippet must therefore avoid writing absolute paths containing a specific username when the user chooses shared SSH config.

## Decision

SSHWarden supports an opt-in multi-device storage mode:

```toml
[storage]
portable = true
multi_device = true
device_id = "auto"

[ssh_config]
path_style = "home_relative"
```

In this mode SSHWarden splits storage into a shared data directory and a current-device data directory:

```text
shared_data_dir/
  config.toml
  local-key-cache.json
  bindings.json
  keys/
  sshwarden_config

shared_data_dir/devices/<device-id>/
  session-<hostname>.enc
  unlock-slots.json
  sshwarden.pid
  sshwarden.log
  run/
```

`config_dir()` remains the shared data directory for backward-compatible callers that manage Bitwarden projection files. New runtime/session callers use `device_data_dir()`.

Shared files:

- `config.toml`
- `local-key-cache.json` (encrypted shared Bitwarden SSH key projection and shared PIN slot)
- `bindings.json`
- `keys/` public selector files
- `sshwarden_config` by default in multi-device mode

Device-local files:

- Bitwarden device session file
- `sshwarden.pid`
- `sshwarden.log`
- runtime socket directory
- `unlock-slots.json` containing Windows Hello / native unlock material for the current device

Platform-native unlock slots are not stored in the shared local key cache in multi-device mode. A startup migration copies older shared Hello/native slots into the current device's `unlock-slots.json`; future cache refreshes strip platform slots from the shared cache.

When `[ssh_config].path_style = "home_relative"`, generated `Include` and `IdentityFile` arguments prefer `~/...` for paths under the current user's home directory. This allows one shared `sshwarden_config` to work across Windows accounts whose OneDrive roots differ only by `C:\Users\<name>`.

`sshwarden forget` changes semantics in multi-device mode: it forgets only the current device's session and native unlock material while preserving the shared local key cache. To remove the shared remembered-secret cache, the user must pass `sshwarden forget --shared-cache`.

## Rationale

- The Bitwarden vault remains the source of truth; the shared local key cache is an encrypted projection intentionally shared by the user.
- Host bindings and public selector files are local preferences but are not device secrets, and sharing them gives consistent OpenSSH key selection across machines.
- PID files, logs, runtime sockets, and refresh-token sessions are inherently device/process-local and should not be cloud-synced as one shared file.
- Windows Hello, macOS Keychain, and Linux Secret Service unlock material is device-local by construction; sharing it would cause devices to overwrite each other's platform unlock state.
- Home-relative OpenSSH paths avoid embedding a particular Windows username into shared snippets.
- Device-only `forget` avoids deleting a shared cache that other devices still use.

## Consequences

- Users who enable multi-device mode should use a strong PIN because the encrypted SSH key projection is intentionally stored in a cloud-synced directory.
- A shared `sshwarden_config` works best when the synced directory has the same path relative to `~` on every device. If not, users can still share `bindings.json` and `keys/` but should configure a device-local managed snippet path.
- If two devices update shared files concurrently, the cloud provider may create conflict copies. Running `sshwarden sync` again from a healthy unlocked device should regenerate the shared cache and selector files from Bitwarden.
- Legacy `vault.enc` remains supported for migration but is not the preferred shared cache format.
