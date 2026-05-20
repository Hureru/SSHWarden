# SSHWarden

SSHWarden is the context for using SSH keys stored in a Bitwarden vault through a local agent while preserving explicit user control over when those keys are usable.

## Language

**SSHWarden**:
A local SSH agent that exposes Bitwarden-managed SSH keys to SSH client applications.
_Avoid_: Bitwarden Desktop, system SSH agent

**Supported Platform**:
A desktop-class operating system on which SSHWarden intends to provide a complete user-facing SSH agent experience: Windows 10/11, Linux desktop sessions, and macOS 13+.
_Avoid_: target, build target, experimental platform, headless platform

**Core Capability**:
A user-visible SSHWarden behavior that must work on every supported platform.
_Avoid_: Windows-only feature, optional feature, compile-time feature

**Baseline Experience**:
The first complete cross-platform SSHWarden experience built from core capabilities and common unlock methods, without requiring platform-native unlock methods.
_Avoid_: minimal build, partial support, native unlock experience

**Common Unlock Method**:
An unlock method that is expected to work on every supported platform without relying on platform-native identity facilities.
_Avoid_: platform unlock method, fallback-only method

**Platform Unlock Method**:
An unlock method backed by a supported platform's native identity or secret-storage facilities.
_Avoid_: core capability, login method

**PIN Unlock**:
A common unlock method where the user enters a PIN to make locally stored SSH keys usable again.
_Avoid_: login, master password unlock

**Agent Endpoint**:
The local address where SSH client applications connect to SSHWarden as an SSH agent.
_Avoid_: control channel, Bitwarden server URL, shell integration

**Shell Integration**:
The user-facing mechanism that makes SSH client applications discover SSHWarden as their SSH agent from a shell environment.
_Avoid_: daemon startup, socket implementation

**Environment Export**:
A shell-specific command output that configures a shell to use SSHWarden's agent endpoint.
_Avoid_: daemon install, login item, control command

**Key Selector File**:
A public-key file named from a key's display name and vault item id prefix, used by SSH client configuration to select one SSHWarden key without exposing private key material.
_Avoid_: private key file, exported key, local key cache

**Key Selector Alias**:
An older key selector file name retained after a key rename so existing SSH client configuration keeps working.
_Avoid_: duplicate key, stale key, private key copy

**SSH Config Snippet**:
A suggested SSH client configuration block that uses a key selector file to choose one SSHWarden key.
_Avoid_: automatic agent filtering, private key export

**Host Binding**:
A local mapping from a **Vault Item Id** to one or more OpenSSH `Host` patterns, used to generate managed SSH client configuration.
_Avoid_: Bitwarden vault metadata, server-side key policy, agent-side filtering

**Managed SSH Config**:
The SSHWarden-generated OpenSSH config file included from `~/.ssh/config` that contains Host Binding-derived `IdentityFile` and `IdentitiesOnly yes` rules.
_Avoid_: exported private key, user-authored SSH config, Bitwarden-synced state

**Startup Integration**:
The user-facing setup that starts SSHWarden automatically in a supported platform's desktop login session.
_Avoid_: shell integration, environment export, service daemon

**Standard Storage**:
The default user data location chosen according to each supported platform's conventions.
_Avoid_: portable mode, executable directory

**Portable Mode**:
An explicit user choice to keep SSHWarden's user data together with the application files.
_Avoid_: default storage, standard installation

**Agent Takeover**:
A user's explicit choice for SSHWarden to become the SSH agent used by SSH client applications in a shell or desktop session.
_Avoid_: agent chaining, transparent proxying, fallback agent

**Control Command**:
A user command that asks a running SSHWarden daemon to report or change its state.
_Avoid_: SSH request, signing request, agent protocol message

**Control Channel**:
The local IPC path used by control commands to communicate with the running SSHWarden daemon.
_Avoid_: SSH agent socket, shell integration

**Diagnostic Check**:
A user-facing investigation of SSHWarden setup, connectivity, platform integration, and likely misconfiguration.
_Avoid_: status, sync, health check

**Bitwarden Vault**:
The user's Bitwarden account data that contains SSH key items.
_Avoid_: local vault, vault file, cache

**Local Key Cache**:
A refreshable local encrypted snapshot of SSH keys that lets SSHWarden unlock previously synced keys without contacting Bitwarden.
_Avoid_: vault, Bitwarden vault, session file, source of truth

**Cache Refresh**:
The act of updating the local key cache from the current Bitwarden vault data after a successful sync.
_Avoid_: login, unlock, authorization

**Stale Cache**:
A local key cache that no longer matches the latest SSH keys known by the running daemon.
_Avoid_: locked cache, corrupted cache, sync failure

**Bitwarden Unreachable**:
A state where SSHWarden cannot contact the configured Bitwarden service even though local SSH client activity may still occur.
_Avoid_: offline, no network, logged out

**Notification Hub**:
The Bitwarden-compatible server push endpoint that notifies SSHWarden about vault changes and logout events.
_Avoid_: sync endpoint, control channel, SSH agent endpoint

**Fallback Sync**:
A sync performed after notification delivery appears unavailable despite reconnect attempts.
_Avoid_: healthy notification polling, manual sync, cache refresh

**Pending Sync**:
A remembered need to sync after unlock because a vault change was observed or fallback sync became due while SSHWarden was locked.
_Avoid_: stale cache, failed sync, notification event

**Remembered Device**:
A device where SSHWarden has a local key cache that can be unlocked without logging in to Bitwarden.
_Avoid_: trusted device, logged-in device, enrolled device

**Ephemeral Session**:
A session where SSHWarden uses SSH keys only for the current daemon lifetime and does not create a local key cache.
_Avoid_: remembered device, portable mode, incognito mode

**SSH Key**:
A Bitwarden vault item containing an SSH private key used for SSH authentication or signing.
_Avoid_: cipher, PEM, key tuple

**Key Identity**:
The public, listable identity of an SSH key, including its public key and display name but not its private key.
_Avoid_: SSH key, private key, cache entry

**Vault Item Id**:
The Bitwarden identifier that links a local key identity back to its source SSH key item.
_Avoid_: cipher id, local key id, public key fingerprint

**SSH Client Application**:
A local process that asks SSHWarden to list keys or sign data.
_Avoid_: app, process, caller

**Key List Request**:
A request from an SSH client application to discover which SSH keys are available.
_Avoid_: sync, fetch keys

**Signing Request**:
A request from an SSH client application to use one SSH key to sign data.
_Avoid_: login request, unlock request

**Authorization**:
The user's approval or denial of a signing request.
_Avoid_: authentication, unlock, consent

**Authorization Memory**:
A temporary remembered approval for a vault item id and operation kind that lasts until lock or session boundary.
_Avoid_: unlock memory, trusted application, permanent approval

**Operation Kind**:
The user-facing kind of signing request, such as SSH authentication or Git signing.
_Avoid_: namespace, protocol field, process name

**Request Context**:
The user-facing explanation of which client, key identity, and operation kind caused a signing-related prompt.
_Avoid_: raw protocol fields, debug metadata

**Lock**:
A state in which SSH keys and local cache refresh capability are not usable by SSH client applications or background sync.
_Avoid_: logout, sign out, background refresh

**Unlock**:
The act of making previously stored SSH keys usable again without necessarily logging in to Bitwarden.
_Avoid_: login, authentication

**Forget**:
The act of removing local remembered key and session material so SSHWarden must log in to Bitwarden before using SSH keys again on that device.
_Avoid_: lock, logout, uninstall, reset configuration

**Login**:
Authentication to Bitwarden that allows SSHWarden to read current vault data.
_Avoid_: unlock

**Unlock Method**:
A user-facing way to unlock SSH keys after they have already been stored locally.
_Avoid_: login method, authentication method

## Relationships

- **SSHWarden** has Windows 10/11, Linux desktop sessions, and macOS 13+ as **Supported Platforms**.
- A **Core Capability** must work on every **Supported Platform**.
- **Startup Integration** is a **Core Capability**.
- Linux **Startup Integration** defaults to desktop-session autostart rather than a headless user service.
- macOS **Startup Integration** defaults to a LaunchAgent for the CLI daemon.
- The **Baseline Experience** is composed of **Core Capabilities** and **Common Unlock Methods**.
- **Standard Storage** is the default on every **Supported Platform**.
- **Portable Mode** is opt-in and replaces **Standard Storage** for users who choose portability.
- A **Common Unlock Method** works across **Supported Platforms**.
- A **Platform Unlock Method** may differ between **Supported Platforms**.
- **PIN Unlock** is a **Common Unlock Method**.
- Platform-native unlock evolves after the **Baseline Experience**, starting with Windows Hello, then macOS Keychain with user presence, then Linux Secret Service-based native unlock.
- A **Bitwarden Vault** contains zero or more **SSH Keys**.
- The **Bitwarden Vault** is the authoritative source for **SSH Keys**.
- A **Notification Hub** can trigger sync when the **Bitwarden Vault** changes.
- **Fallback Sync** backs up the **Notification Hub** only after reconnect attempts indicate notifications are degraded.
- While locked, **Notification Hub** events and due **Fallback Sync** create **Pending Sync** instead of pulling and decrypting vault data.
- **Pending Sync** is resolved after **Unlock** by syncing before normal cached signing when possible.
- If **Pending Sync** cannot be resolved because **Bitwarden Unreachable**, a **Remembered Device** may still sign with an unlocked **Local Key Cache**.
- A **Local Key Cache** contains encrypted previously synced **SSH Keys**, listable **Key Identities**, and their **Vault Item Ids**.
- An **SSH Key** has a **Key Identity** and a **Vault Item Id**.
- **Cache Refresh** updates a **Local Key Cache** from the **Bitwarden Vault** after a successful sync.
- A successful sync makes the running SSH key set mirror the current active SSH keys in the **Bitwarden Vault**.
- A successful **Cache Refresh** makes the **Local Key Cache** mirror the current active SSH keys in the **Bitwarden Vault**.
- A successful sync refreshes the running SSH key set and attempts **Cache Refresh** when the device is remembered.
- A successful sync on a **Remembered Device** updates **Key Selector Files** by default.
- A **Stale Cache** can exist when sync succeeds but **Cache Refresh** cannot be completed.
- A **Remembered Device** has a **Local Key Cache**.
- A **Remembered Device** may sign with an unlocked **Local Key Cache** while **Bitwarden Unreachable**.
- An **Ephemeral Session** does not create a **Local Key Cache**.
- **SSHWarden** exposes unlocked **SSH Keys** to **SSH Client Applications**.
- An **Agent Endpoint** is separate from the **Control Channel**.
- Unix-like **Agent Endpoints** use per-user runtime locations by default.
- **Shell Integration** uses **Environment Export** for shell-launched **SSH Client Applications**.
- A **Key Selector File** lives under the user's SSHWarden configuration storage and helps an **SSH Client Application** choose a specific **Key Identity** and avoid trying every agent key.
- A **Key Selector Alias** continues to select the same **Vault Item Id** after a key rename.
- An **SSH Config Snippet** is printed by default and only written to SSH configuration when the user explicitly asks.
- A **Host Binding** maps one **Vault Item Id** to OpenSSH host patterns on the local device.
- **Managed SSH Config** is generated from **Host Bindings** and **Key Selector Files** so OpenSSH offers only the intended key for a host.
- **Shell Integration** enables **Agent Takeover** for **SSH Client Applications** launched from that shell.
- During **Agent Takeover**, an **SSH Client Application** sends requests to **SSHWarden** through an **Agent Endpoint** rather than to another local SSH agent.
- A **Control Command** uses the **Control Channel**, not the SSH agent socket.
- A **Control Command** does not start the daemon unless the user explicitly asks it to.
- Status reports current SSHWarden state; a **Diagnostic Check** investigates setup problems.
- A **Diagnostic Check** is read-only unless the user explicitly asks for repair.
- An **SSH Client Application** may make **Key List Requests** and **Signing Requests**.
- A **Signing Request** uses exactly one **SSH Key**, has one **Operation Kind**, and may require **Authorization**.
- **Authorization Memory** remembers **Authorization** for one **Vault Item Id** and one **Operation Kind** until **Lock**, a session boundary, or a key material change for that item.
- **Lock** prevents **SSH Client Applications** from using **SSH Keys** for signing and prevents **Cache Refresh** until **Unlock** succeeds on a **Remembered Device**.
- A **Remembered Device** starts locked and may expose **Key Identities** before **Unlock**.
- **Key Identities** may remain listable while **SSHWarden** is locked.
- A **Signing Request** while locked may trigger **Unlock**; a **Key List Request** while locked does not trigger **Unlock**.
- Automatic **Unlock** presents **Request Context** and is followed by separate **Authorization** when unlock succeeds.
- In an **Ephemeral Session**, **Lock** requires a future **Login** before **SSH Keys** can be used again.
- **Forget** removes local remembered key and session material including the **Local Key Cache**, device sessions, and platform unlock enrollment.
- **Forget** does not remove user preferences, installation state, shell integration, or logs.
- **Login** reads current **SSH Keys** from the **Bitwarden Vault** and normally creates a **Remembered Device** by establishing **PIN Unlock** and a **Local Key Cache**.
- **Unlock** restores usability of **SSH Keys** from the **Local Key Cache**.
- An **Unlock Method** performs **Unlock**, not **Login**.

## Example dialogue

> **Dev:** "When Git asks SSHWarden to sign a commit, is that an unlock?"
> **Domain expert:** "No. Git creates a **Signing Request**. If SSHWarden is locked, the user must **Unlock** first; after that, the **Signing Request** may still require **Authorization**."

## Flagged ambiguities

- "vault" can mean the **Bitwarden Vault** or a local encrypted cache. Resolved: use **Bitwarden Vault** for the user's Bitwarden data and **Local Key Cache** for locally stored encrypted SSH keys.
- "cache" means a refreshable local snapshot; it is not the authoritative source for SSH keys.
- "active SSH key" means an SSH key in the **Bitwarden Vault** that is neither deleted nor archived.
- "mirror" means current active SSH keys from the **Bitwarden Vault**; deleted, archived, or unavailable vault items are not retained after successful sync.
- "stale cache" means the running daemon may have newer SSH keys than the **Local Key Cache** that will be used after restart.
- "offline signing" means signing while **Bitwarden Unreachable** using an unlocked **Local Key Cache**; it does not require the entire network to be unavailable.
- "pending sync failed" does not by itself block cached signing unless a stricter future policy requires a successful online sync.
- "notification hub" means Bitwarden-compatible server push for vault changes; it is not the SSHWarden control channel or SSH agent endpoint.
- "fallback sync" means sync after notification reconnect attempts fail or exceed a configured threshold; it is not blind polling while the **Notification Hub** is healthy.
- "pending sync" means sync should run after unlock; it is not itself evidence that the local key cache is stale or corrupted.
- "unlock" and "login" are different. Resolved: **Login** talks to Bitwarden to read current vault data; **Unlock** makes already stored keys usable again.
- "lock" and "forget" are different. Resolved: **Lock** temporarily prevents signing with remembered SSH keys and local cache refresh capability; **Forget** removes remembered key and session material so a future **Login** is required.
- "key identity" is listable public metadata and must not be treated as private key material.
- "local key cache header" may expose **Key Identities** and **Vault Item Ids** while private SSH key material remains encrypted.
- "cipher id" in code corresponds to **Vault Item Id** in domain language.
- "startup" of a **Remembered Device** means locked with listable **Key Identities**, not automatic unlock.
- "auto unlock" is a response to a **Signing Request**, not to a **Key List Request**.
- "unlock prompt" and "authorization prompt" are separate prompts even when they share the same **Request Context**.
- "forget" does not mean uninstalling SSHWarden, deleting preferences, removing shell integration, or clearing logs.
- "remembered device" means local key material can be unlocked on that device; it does not mean Bitwarden account trust or permanent login.
- "no cache" means an **Ephemeral Session** where keys are not remembered after the daemon lifetime.
- "unlock" is unavailable after **Lock** in an **Ephemeral Session** because there is no **Local Key Cache** to restore from.
- "authorization" and "authentication" are different. Resolved: **Authorization** approves a **Signing Request**; authentication proves user identity to Bitwarden or to an unlock method.
- "remember authorization" means **Authorization Memory** for a **Vault Item Id** and **Operation Kind**, not a permanent trust relationship with an application.
- "key rename" does not clear **Authorization Memory**; key material change for the same **Vault Item Id** does.
- "cross-platform" means every **Supported Platform** gets a complete user-facing SSH agent experience, not merely that the project compiles there.
- "supported platform" excludes WSL, BSD, mobile, browser, and headless server environments unless they are explicitly promoted later.
- "complete user-facing SSH agent experience" means **Core Capabilities** are equivalent across **Supported Platforms**, while **Platform Unlock Methods** may use different native facilities.
- "PIN" means **PIN Unlock**, a cross-platform unlock capability, not a Bitwarden login credential.
- "native unlock" means a **Platform Unlock Method**; it is not required for the **Baseline Experience**.
- "macOS native unlock" means Keychain-protected local cache key access with user presence such as Touch ID or system password.
- "Linux native unlock" means Secret Service-compatible secret storage by default, not Polkit as the primary storage mechanism.
- "baseline" means **Baseline Experience**, not reduced or experimental platform support.
- "portable" means **Portable Mode**, an explicit storage choice; it is not the default cross-platform installation model.
- "agent endpoint" means the SSH agent protocol endpoint, not the control IPC endpoint.
- "Unix agent endpoint" means a per-user runtime socket by default, not a dotfile socket in the home directory.
- "environment export" defaults to POSIX shell syntax and may support additional shell syntaxes.
- "key selector file" contains public key material only and exists to guide SSH client key selection.
- "key selector file location" is the `keys/` area under SSHWarden's standard configuration storage, not runtime storage.
- "key selector file name" uses a slugified display name plus a vault item id prefix, so key rotation updates file contents without changing the SSH config path.
- "key selector file update" follows successful sync on remembered devices unless the user disables it.
- "key selector alias" is kept after rename to avoid breaking SSH config and is removed when the underlying vault item is deleted or archived.
- "ssh config snippet" is advice by default; modifying SSH configuration requires explicit write intent.
- "startup integration" means launching SSHWarden in the user's desktop login session, not configuring a shell to find the agent endpoint.
- "Linux startup integration" means XDG Autostart by default; systemd user services are optional or future advanced integration.
- "macOS startup integration" means LaunchAgent by default; Login Item integration is optional or future app-bundle integration.
- "shell integration" means discovery of SSHWarden by shell-launched SSH client applications, not starting or installing the daemon.
- "agent takeover" is explicit replacement of the active SSH agent in a user environment; it does not mean proxying or chaining to an existing agent.
- "control" means **Control Command** over the **Control Channel**; it does not mean an SSH agent protocol request.
- "control command failed to connect" means the daemon is not reachable; it is not itself a request to start the daemon.
- "doctor" means **Diagnostic Check**, not status reporting or automatic repair.
- "doctor --fix" means explicit repair; plain "doctor" must not modify user or system configuration.
