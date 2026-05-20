# Host bindings and managed SSH config

## Status

Accepted

## Context

SSHWarden can expose many Bitwarden-managed SSH keys through one local SSH agent. OpenSSH may offer several agent identities to a server before it reaches the correct key. Servers commonly disconnect after `MaxAuthTries=6`, so users with many vault keys can fail authentication even though the right key is available.

The SSH agent protocol does not include the destination host in key list requests. By the time SSHWarden receives a signing request, OpenSSH has already selected a key to try. Therefore SSHWarden cannot reliably solve host-specific key selection by filtering `REQUEST_IDENTITIES` inside the agent.

## Decision

SSHWarden stores local host bindings in `bindings.json` and generates an OpenSSH-readable managed config file at `~/.ssh/sshwarden_config`. The user's `~/.ssh/config` includes that file through a single SSHWarden-managed Include line.

Each host binding maps a vault item id to one or more OpenSSH `Host` patterns. The generated block uses a public Key Selector File and `IdentitiesOnly yes`:

```sshconfig
Host github.com
    IdentityFile ".../keys/github-key--abcd1234.pub"
    IdentitiesOnly yes
```

The binding data remains local to the device rather than being stored in Bitwarden item metadata.

The bind-hosts UI can be launched from a signing authorization prompt. In that flow, **Bind & Approve** saves the binding and approves the original signing request in one action.

SSHWarden best-effort infers the target host by reading the SSH client process command line. Inference failure is non-fatal and falls back to an empty host field.

## Rationale

- Local `bindings.json` avoids depending on Bitwarden backend schema changes and works with cached/offline key identities.
- Managed OpenSSH config solves the problem at the SSH client selection layer, before the server counts failed key attempts.
- Public Key Selector Files do not expose private key material.
- `~/.ssh/config` remains necessary even in portable mode because OpenSSH reads user configuration from fixed SSH paths, not SSHWarden's config directory.
- One-click **Bind & Approve** avoids asking the user to approve the same signing request twice.
- Process command-line inspection is platform- and permission-dependent, so it must remain best-effort and must not be security-critical.

## Consequences

- SSHWarden has a small OpenSSH footprint outside its config directory: `~/.ssh/config` and `~/.ssh/sshwarden_config`.
- Bindings are per-device local preferences, not Bitwarden-synced state.
- SSHWarden must preserve compatibility with older unquoted Include lines and must quote generated paths so spaces in platform-standard directories work.
- Users can create broad patterns such as `*`; SSHWarden warns because such patterns can reintroduce `MaxAuthTries` failures.
