# Host bindings and SSH config

Host bindings tell OpenSSH which SSHWarden key should be offered for each SSH host. This avoids the common `MaxAuthTries=6` failure when a vault contains many SSH keys.

## The problem

OpenSSH asks the configured SSH agent for identities and may try several keys before it reaches the right one. Many servers disconnect after a small number of failed public-key attempts, commonly six. If SSHWarden exposes more keys than the server allows attempts, authentication can fail before OpenSSH tries the correct key.

## How SSHWarden solves it

SSHWarden writes public **Key Selector Files** for vault keys and can generate a managed SSH config file. By default this file is kept beside the running executable:

```text
<exe-dir>/sshwarden_config
```

You can override it in `config.toml`; `~`, `~/...`, and `~\\...` are expanded:

```toml
[ssh_config]
managed_path = "~/private/sshwarden_config"
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
Include "<resolved-managed-path>"
```

The managed file is regenerated from local bindings and the local key cache. You may edit the `Host` lines inside SSHWarden key blocks; SSHWarden imports those host patterns before regenerating the file. Other lines are treated as generated output.

## Quickstart

After logging in or syncing once so SSHWarden has a local key cache:

```bash
sshwarden login
sshwarden keys bind github-key github.com
ssh github.com
```

You can use either the key display name or the vault item id shown by `sshwarden keys`.

Useful commands:

```bash
sshwarden keys                                        # list keys + bindings + ssh-config status
sshwarden keys bind github-key github.com gitlab.com
sshwarden keys unbind github-key github.com
sshwarden keys unbind github-key --all
sshwarden ssh-config show
sshwarden ssh-config write                            # regenerate snippet + ensure Include
```

## GUI path

When a signing request appears for an unbound host, choose **Bind & Approve...**. SSHWarden opens the Bind Hosts dialog, preselects the requested key, and best-effort pre-fills the SSH host by inspecting the client process command line.

If the prefill is empty, type the hostname manually. Process inspection can fail on hardened Linux/macOS systems, sandboxed packages, or if the SSH process exits too quickly.

Saving from this flow also approves the original signing request.

## File layout

- `bindings.json` — local mapping from vault item id to host patterns, stored under SSHWarden's configuration directory.
- `keys/*.pub` — public Key Selector Files, stored under SSHWarden's configuration directory.
- `<exe-dir>/sshwarden_config` by default, or `[ssh_config].managed_path` when configured — OpenSSH-readable managed config generated from bindings.
- `~/.ssh/config` — contains one SSHWarden Include line.

OpenSSH still reads the user's main config from fixed SSH paths, so `~/.ssh/config` remains the unavoidable OpenSSH footprint. The generated SSHWarden snippet no longer defaults to the device-wide `.ssh` directory.

## Uninstalling

Remove the Include line:

```bash
sshwarden ssh-config remove
```

This preserves the managed snippet and `bindings.json`. Delete them manually if you want a fully clean setup.

## Troubleshooting

### Include line missing

Run:

```bash
sshwarden ssh-config write
```

Then confirm with:

```bash
sshwarden ssh-config
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
