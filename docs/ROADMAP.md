# SSHWarden Roadmap

This roadmap tracks implementation work needed to align the codebase with the current product language in `CONTEXT.md` and architectural decisions in `docs/adr/`.

## P0 — Make the current project state reliable

- Fix `cargo test --workspace` by updating or removing stale UI examples.
- Update `config.toml.example` so it does not imply completed cross-platform parity or portable-by-default storage.
- Improve sync freshness:
  - fix SignalR notification URL construction for Bitwarden cloud vs self-hosted/Vaultwarden,
  - resolve service URLs using explicit config, then `/api/config` discovery, then built-in defaults,
  - restore/connect API session and notifications after any successful unlock path,
  - reconnect or restart notifications after access token refresh; the token refresh tick is 5 minutes because the hub rejects a stale token with HTTP 401,
  - track notification connection state; implemented through a per-transition status stream and reported by `status`/`doctor`; see ADR 0026,
  - accept both text and binary SignalR initial responses,
  - send SignalR MessagePack ping every 30 seconds and treat 90 seconds of inactivity as stale,
  - use reconnect-first fallback sync after notification failures instead of blind polling while WebSocket is healthy; a lost established connection also requests a throttled recovery sync because no supported hub can replay missed events; see ADR 0026.
- Address SSH authentication failures when many keys are loaded: completed through local host bindings, public Key Selector Files, and managed OpenSSH config. See `docs/host-bindings.md` and ADR 0023.

## P1 — Cross-platform baseline infrastructure

- Standard storage by default; portable mode opt-in.
- Machine-local runtime state (PID file, log, runtime sockets) outside the shared data directory, with a bounded log — implemented; see ADR 0025.
- Configurable agent endpoint on every platform.
- Unix runtime agent socket paths.
- Cross-platform control channel: Windows named pipe, Unix control socket.
- `sshwarden env` environment export.
- Cross-platform startup integration:
  - Windows Startup folder shortcut,
  - macOS LaunchAgent,
  - Linux XDG Autostart.
- `status --json` and read-only `doctor`; `doctor --fix` for explicit repair.

## P2 — Local Key Cache model

- Replace direct PIN/platform encryption of cached SSH keys with envelope encryption.
- Store Key Identities and Vault Item Ids in a readable cache header.
- Keep private key payload encrypted by Local Cache Key.
- Refresh Local Key Cache after successful sync when unlocked and remembered.
- Track and report Stale Cache.
- Implement Forget.

## P3 — Authorization and lock semantics

- Keep Key Identities listable while locked.
- Do not unlock for Key List Requests.
- Unlock only for Signing Requests.
- Show Request Context in automatic unlock prompts.
- Implement RememberUntilLock as Vault Item Id + Operation Kind.
- Clear authorization memory on lock, session boundary, daemon restart, key deletion/archive, or key material change.
- Always require approval for agent forwarding.
- Order identities per connection by Selection Rule, Host Binding, and Selection History; opt-in Key Picker (ADR 0027). Done on Linux; session-bind and argv reading still need verification on Windows and macOS.
- Later: CLI/GUI for Selection Rules, and Key Selection state in `status` / `doctor`.

## P4 — Platform-native unlock

- Migrate Windows Hello to envelope encryption.
- Add macOS Keychain + user presence / Touch ID native unlock.
- Add Linux Secret Service-compatible native unlock.

## Known issues

- **Audit backlog (2026-11):** 28 numbered findings with evidence, file
  references, fix sketches and a fix order are in `docs/audit-2026-11.md`.

- **Some ECDSA keys do not load.** OpenSSH stores the private number of an
  ECDSA key without its leading zero bytes, and `ssh-key` 0.6.7 refuses the
  shorter form ("Failed to parse key: length invalid"). About half of all
  P-521 keys and one in 256 P-256 or P-384 keys are affected. The agent then
  does not offer the key; the log has an ERROR line, but `login` and `sync`
  still count the key as loaded. Ed25519 and RSA keys are not affected. Seen
  2026-11 with a generated P-521 key; not fixed, since the fix is to re-pad
  the number before parsing or to wait for a newer `ssh-key`.

- **Linux dialog is rendered at 800×600 with content in the top-left 380×230
  area** on Wayland (observed on niri) when Slint uses the femtovg renderer.
  Root cause is a window min/max-size constraint being overwritten inside the
  Slint winit backend; see `docs/linux-dialog-size-investigation.md` and the
  repro at `crates/sshwarden-ui/examples/repro_linux_dialog.rs`. Not fixed
  upstream as of Slint 1.15; candidate fixes are noted in that document.
