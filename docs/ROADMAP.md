# SSHWarden Roadmap

This roadmap tracks implementation work needed to align the codebase with the current product language in `CONTEXT.md` and architectural decisions in `docs/adr/`.

## P0 — Make the current project state reliable

- Fix `cargo test --workspace` by updating or removing stale UI examples.
- Update `config.toml.example` so it does not imply completed cross-platform parity or portable-by-default storage.
- Mark `llmdoc/` legacy notes as reference material where needed; `CONTEXT.md` and ADRs are authoritative.
- Improve sync freshness:
  - fix SignalR notification URL construction for Bitwarden cloud vs self-hosted/Vaultwarden,
  - resolve service URLs using explicit config, then `/api/config` discovery, then built-in defaults,
  - restore/connect API session and notifications after any successful unlock path,
  - reconnect or restart notifications after access token refresh,
  - track notification connection state,
  - accept both text and binary SignalR initial responses,
  - send SignalR MessagePack ping every 30 seconds and treat 90 seconds of inactivity as stale,
  - use reconnect-first fallback sync after notification failures instead of blind polling while WebSocket is healthy.
- Address SSH authentication failures when many keys are loaded:
  - document OpenSSH key-offer behavior and `MaxAuthTries`,
  - add key selection workflow based on public-key selector files and SSH config snippets,
  - implement a P0 command for writing public key selector files from current SSHWarden keys.

## P1 — Cross-platform baseline infrastructure

- Standard storage by default; portable mode opt-in.
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

## P4 — Platform-native unlock

- Migrate Windows Hello to envelope encryption.
- Add macOS Keychain + user presence / Touch ID native unlock.
- Add Linux Secret Service-compatible native unlock.
