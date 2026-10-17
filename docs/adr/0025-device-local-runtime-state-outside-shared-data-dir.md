# Machine-local runtime state lives outside the shared data directory

## Status

Accepted

## Context

ADR 0024 split one portable directory into a shared data directory and a per-device directory under `devices/<device-id>/`. That stops two machines from overwriting each other's files, but every file still lives inside the shared root — which for the users this feature exists for is a **cloud-synced** directory such as OneDrive.

Keeping `sshwarden.pid` and `sshwarden.log` there has consequences that per-device subdirectories do not fix:

- **PID semantics.** A PID only means something on the machine that wrote it. After syncing, `pid_file_owner_alive` compares the foreign PID against local processes; an unlucky match with the executable name reports "already running" and blocks a healthy start. Conversely, a synced PID file makes `create_new`-based claiming less meaningful.
- **Log churn.** The daemon appends to the log without a size cap. In a synced folder that means continuous upload, unbounded growth, and conflict copies (`sshwarden.log-<machine>`), none of which carry information for the other machines.
- **Sockets.** Unix sockets cannot live on a cloud-synced filesystem; on macOS the previous fallback put `run/` inside the data root.
- **User data hygiene.** Users reasonably expect the synced folder to contain the things they chose to share, not per-machine runtime noise.

The same ADR already declares this state device-local; only its *location* kept it inside the shared tree.

## Decision

Machine-local runtime state has its own directory, resolved by `sshwarden_config::local_state_dir()`, and never lives inside the shared data root:

| State | Location |
|---|---|
| `sshwarden.pid` | `<local_state_dir>/sshwarden.pid` |
| `sshwarden.log` (+ `.log.1`) | `<local_state_dir>/sshwarden.log` |
| Unix socket directory | `$XDG_RUNTIME_DIR/sshwarden` (Linux), `$TMPDIR/sshwarden` (macOS), `<local_state_dir>/run` fallback |

Resolution priority:

1. `SSHWARDEN_LOCAL_HOME` environment variable (used verbatim).
2. `[storage] local_dir` (`~` expands; relative paths resolve under the shared data directory; used verbatim).
3. Platform-local default plus a per-instance subdirectory:
   - Windows: `%LOCALAPPDATA%\SSHWarden\<instance>`
   - Linux: `$XDG_STATE_HOME/sshwarden/<instance>` (default `~/.local/state/sshwarden/<instance>`)
   - macOS: `~/Library/Application Support/SSHWarden/<instance>`

`<instance>` is the device id in multi-device mode, otherwise the shared data root's own directory name, so two installations on one machine cannot fight over a single PID file.

None of the platform defaults are covered by OneDrive known-folder backup or iCloud Drive.

Log rotation: `[logging] max_file_bytes` (default 5 MiB, `SSHWARDEN_LOG_MAX_BYTES` override, `0` disables) rotates to a single `sshwarden.log.1` backup. Rotation failure warns once and keeps appending rather than dropping records.

Shared files are unchanged: `config.toml`, `local-key-cache.json`, `bindings.json`, `keys/`, and (by default in multi-device mode) `sshwarden_config` stay in the shared data root. `session-<hostname>.enc` and `unlock-slots.json` keep their ADR 0024 placement so the "remembered device" session can still be shared intentionally; multi-device mode remains the way to keep those per machine.

Migration is best effort and idempotent:

- A pre-upgrade log is renamed next to the new one; if the move fails (cross-filesystem), the old file is left untouched and a fresh log starts.
- A legacy PID file is deleted only when its recorded process is not alive. A live daemon started by an older build is still detected through the read-only legacy PID paths, and a new start yields to it instead of racing a second agent onto the same sockets.
- `doctor` reports leftover legacy runtime files and `doctor --fix` cleans them up.

## Rationale

- PID, log, and socket state is per-machine by construction; cloud sync can only add noise, conflicts, and false liveness signals.
- Platform-local directories are the documented place for such state and are excluded from cloud known-folder sync by default.
- An instance subdirectory preserves the isolation that per-data-root paths used to provide implicitly.
- Explicit overrides (`SSHWARDEN_LOCAL_HOME`, `[storage] local_dir`) keep true all-in-one portable deployment possible, where the user accepts the consequence.
- Bounding the log at a size cap removes the one remaining unbounded growth path.

## Consequences

- `sshwarden.log` and `sshwarden.pid` are no longer beside the executable. `status` (including its offline view), `status --json`, and `doctor` report the real paths, and the release notes must call this out.
- Two installations sharing one machine should either use the default per-instance subdirectory or set explicit `local_dir`/`SSHWARDEN_LOCAL_HOME` values.
- A legacy log that cannot be moved stays in the synced directory until the user removes it or runs `doctor --fix`.
- `session-<hostname>.enc` and `unlock-slots.json` remain in the shared tree; multi-device mode is still recommended (and a strong PIN with it) for OneDrive-based installs.
