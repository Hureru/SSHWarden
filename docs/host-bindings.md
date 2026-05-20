# Host bindings and SSH config

Host bindings tell OpenSSH which SSHWarden key should be offered for each SSH host. This avoids the common `MaxAuthTries=6` failure when a vault contains many SSH keys.

## The problem

OpenSSH asks the configured SSH agent for identities and may try several keys before it reaches the right one. Many servers disconnect after a small number of failed public-key attempts, commonly six. If SSHWarden exposes more keys than the server allows attempts, authentication can fail before OpenSSH tries the correct key.

## How SSHWarden solves it

SSHWarden writes public **Key Selector Files** for vault keys and can generate a managed SSH config file at:

```text
~/.ssh/sshwarden_config
```

For every host binding, the managed config contains a `Host` block like:

```sshconfig
Host github.com
    IdentityFile ".../SSHWarden/keys/github-key--abcd1234.pub"
    IdentitiesOnly yes
```

`IdentityFile` points to a public selector file, not private key material. `IdentitiesOnly yes` tells OpenSSH to offer only the selected identity for that host.

SSHWarden also adds one Include line to the user's SSH config:

```sshconfig
# SSHWarden managed key selector snippets
Include "~/.ssh/sshwarden_config"
```

The managed file is regenerated from local bindings and the local key cache.

## Quickstart

After logging in or syncing once so SSHWarden has a local key cache:

```bash
sshwarden login
sshwarden ssh-config install
sshwarden bindings add github-key github.com
ssh github.com
```

You can use either the key display name or the vault item id shown by `sshwarden keys` / `sshwarden bindings list`.

Useful commands:

```bash
sshwarden bindings list
sshwarden bindings add github-key github.com gitlab.com
sshwarden bindings remove github-key github.com
sshwarden bindings clear github-key
sshwarden ssh-config status
sshwarden ssh-config show
sshwarden ssh-config regenerate
```

## GUI path

When a signing request appears for an unbound host, choose **Bind & Approve...**. SSHWarden opens the Bind Hosts dialog, preselects the requested key, and best-effort pre-fills the SSH host by inspecting the client process command line.

If the prefill is empty, type the hostname manually. Process inspection can fail on hardened Linux/macOS systems, sandboxed packages, or if the SSH process exits too quickly.

Saving from this flow also approves the original signing request.

## File layout

- `bindings.json` — local mapping from vault item id to host patterns, stored under SSHWarden's configuration directory.
- `keys/*.pub` — public Key Selector Files, stored under SSHWarden's configuration directory.
- `~/.ssh/sshwarden_config` — OpenSSH-readable managed config generated from bindings.
- `~/.ssh/config` — contains one SSHWarden Include line.

In portable mode, SSHWarden's own config and selector files move to the portable directory, but OpenSSH still reads user config from fixed SSH paths. Therefore `~/.ssh/config` and `~/.ssh/sshwarden_config` remain the unavoidable OpenSSH footprint.

## Uninstalling

Remove the Include line:

```bash
sshwarden ssh-config uninstall
```

This preserves `~/.ssh/sshwarden_config` and `bindings.json`. Delete them manually if you want a fully clean setup.

## Troubleshooting

### Include line missing

Run:

```bash
sshwarden ssh-config install
```

Then confirm with:

```bash
sshwarden ssh-config status
```

### Wrong key offered

Inspect the generated config:

```bash
sshwarden ssh-config show
```

Make sure the host pattern matches the host you use with `ssh`. OpenSSH host matching follows `ssh_config` `Host` pattern rules.

### Bind dialog shows no prefill

SSHWarden could not read the SSH client process command line. This is expected on some hardened or sandboxed systems. Manually type the hostname.

### Binding to `*`

A catch-all pattern is legal OpenSSH config, but it makes the key eligible for many hosts and can reintroduce `MaxAuthTries` failures. Prefer specific hostnames or narrow globs such as `*.prod.example.com`.
