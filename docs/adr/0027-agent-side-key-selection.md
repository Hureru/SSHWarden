# The agent orders identities per connection

## Status

Accepted. Revises the premise of ADR 0023; Host Bindings and the Managed SSH Config stay as they are.

## Context

ADR 0023 concluded that "the SSH agent protocol does not include the destination host in key list requests", so host-specific key selection could only happen in the SSH client's configuration. Every connection therefore received the same full identity list, and in `HashMap` iteration order.

Measured against OpenSSH 10 with a logging proxy in front of a real agent, that premise only holds for old clients:

- OpenSSH 8.9 and later send the `session-bind@openssh.com` extension **before** `REQUEST_IDENTITIES`. It carries the destination's host key and an `is_forwarding` flag.
- The peer process is known as soon as the connection is accepted, and its argv names the destination, the login user, and — when Git drives the client — the remote repository (`git-upload-pack '/owner/repo.git'`).
- `ssh` only requests a signature for a key the server has already accepted, so a signing request for user authentication is evidence of which key that server wants.
- `ssh-add -l` and similar tools send no session-bind and have no SSH target in argv.

Two bugs surfaced during the measurement and are fixed alongside:

- A forwarded connection carries two binds, `is_forwarding=1` followed by the remote hop's `is_forwarding=0`. The agent overwrote the flag each time, so forwarded connections lost their "always require approval" treatment. The flag is now sticky; the host key still follows the last bind, which is the real destination.
- `sysinfo`'s default process refresh does not read the command line, so argv inference (the Bind dialog's host prefill) silently returned nothing. The refresh now asks for it explicitly.

## Decision

**1. The identity list is decided per connection.** The vendored agent library's `can_list` hook is replaced by `identities(connection) -> Option<Vec<Key>>`. The agent asks the host application over a dedicated channel and writes the returned keys in the returned order; a dropped reply fails the list request closed. The channel is separate from the main daemon loop, because that loop can wait on a control action for minutes and listing must not queue behind it.

**2. Selection reorders; it does not filter.** For a connection, keys are ordered by the first source that has an opinion, and every other key still follows in a stable name order:

1. **Selection Rule** — the first `[[rules]]` entry in `config.toml` whose `host`, `user`, and `repo` conditions all hold.
2. **Host Binding** — a binding whose host patterns match the destination typed on the command line.
3. **Selection History** — the keys this context most recently authenticated with.

A wrong guess costs one failed attempt instead of a failed login, which matters because every input below is a hint. With nothing to go on, the order is by display name.

**3. The Key Picker is the only thing that narrows the list, and it is opt-in.** With `[agent] key_picker = true`, a real authentication (host key or SSH target known) with more than one key and no preference shows a dialog; the chosen key is the only one offered. Cancelling or timing out (100 seconds, inside sshd's default `LoginGraceTime`) offers nothing. Picks are serialized and reused for 30 seconds so parallel connections to the same context produce one dialog.

Picking a key counts as approving its use on that connection, so the authorization prompt is skipped for it — except on forwarded connections, which always prompt. A reused pick for a parallel connection does not count: those go through normal authorization.

**4. argv is a hint, never a security input.** Any local process can run with a forged command line. argv therefore only influences order and what the picker displays; it never decides whether a request is approved. On forwarded connections argv describes the first hop, not the destination, so it is ignored there and only the bound host key is used.

**5. History is recorded when the signature is requested, not when it is approved.** The record is "this server accepted this key", which is true regardless of the user's answer. It is keyed by host key fingerprint (falling back to the typed host for clients without session-bind) plus the first path segment of the Git repository, so several accounts on one Git host are remembered separately. It keeps the three most recent keys per context in `key-history.json` in the device data directory, written with private-file permissions.

**6. `bitwarden-russh` is vendored into `crates/`.** Upstream is deprecated, and decision 1 needs a trait change. The copy is pinned at commit `a641316`; the only functional difference is the `identities` hook.

## Rationale

- Ordering fixes the `MaxAuthTries` problem for the common case without asking users to maintain bindings: after one successful login the right key is offered first.
- Not filtering keeps a stale rule, a renamed host alias, or a forged argv from locking a user out or hiding a key.
- Rules cover what bindings cannot express: OpenSSH `Host` matching sees one hostname for all of `github.com`, while the agent can see which repository is being fetched.
- The host key fingerprint is a better history key than the typed hostname: it is the same for aliases, IPs, and `ProxyJump` routes to one server, and it is not under the local caller's control.
- Making the picker opt-in keeps the default flow free of an extra dialog; history makes it rare even when enabled.

## Consequences

- Host Bindings still matter: `IdentitiesOnly yes` is the only way to offer exactly one key without a dialog, and the only mechanism that works for clients without session-bind when argv is unreadable.
- Binding patterns are matched in the agent with a small glob matcher (`*`, `?`, `!` negation) against the destination as typed. `ssh_config` aliases match by their alias, as in OpenSSH; `HostName` rewriting is not followed.
- The repository-owner part of the history key is a heuristic: for `ssh://` remotes with deep server paths the first segment is not an owner. The effect is coarser or finer history grouping, never a wrong authorization.
- `key-history.json` records fingerprints of visited servers' host keys, comparable to an unhashed `known_hosts`.
- Each list request costs one in-process round trip. If the selector cannot load rules, bindings, or history it falls back to the full name-ordered list.
- Rules are edited by hand in `config.toml` and read at daemon start; there is no CLI or GUI for them yet.
- Session-bind and argv reading were verified on Linux with OpenSSH 10. Windows and macOS are unverified; the OpenSSH shipped with older Windows 10 builds predates session-bind and relies on argv alone.
