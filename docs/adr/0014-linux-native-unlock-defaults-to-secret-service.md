# Linux native unlock defaults to Secret Service

SSHWarden's future Linux native unlock should use Secret Service-compatible desktop keyrings as the default mechanism for protecting the local cache key, with PIN unlock as the fallback when no suitable service is available. Polkit may be considered for authentication prompts or privileged actions, but it is not the default secret storage mechanism because SSHWarden needs to wrap or retrieve a local cache key, not merely authorize an action.

## Update (2026-11): the keyring does not undo a lock

A keyring unlock asks the user nothing. So after `sshwarden lock` the next sign request unlocked the vault again without a prompt, and with `prompt_behavior = "never"` it signed at once: the lock (ADR 0009) was no boundary.

- The silent keyring unlock (a sign request, or `sshwarden unlock` with no method) works from the start of the daemon until the first lock, by hand or by timeout. After that the user has to enter the PIN. A restart of the daemon turns it on again.
- `sshwarden unlock --method native` still uses the keyring after a lock: the user typed it.
- What this does not change: while the vault is locked, the Local Cache Key is still in the login keyring, and any process of the same user can read it there and open the Local Key Cache file without the agent. That is how a login keyring works. Who needs lock to hold against other processes of the same user should not enroll the keyring and use the PIN only.
