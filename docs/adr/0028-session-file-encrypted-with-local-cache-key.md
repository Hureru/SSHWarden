# The session file holds the refresh token and the user key, encrypted with the Local Cache Key

## Status

Accepted

## Context

The session file (`session-<hostname>.enc`) let the daemon get a Bitwarden access token back after a restart without the master password. Version 1 stored only the refresh token, once encrypted with the PIN and once with Windows Hello.

That had three faults:

- **No user key.** The user key (the key that opens vault items) was only set by a master-password login. After a restart and a PIN unlock the daemon was "logged in" but every sync failed with "Bitwarden session cannot decrypt vault data", and a key deleted on the server kept signing.
- **No session after a native unlock.** There was no keyring-encrypted token, so a keyring unlock restored nothing.
- **A weak PIN wrapper.** The PIN-encrypted token used the fixed public salt that SEC-04 had already removed from the Local Key Cache.

Every unlock method (PIN, Windows Hello, native keyring) already recovers one secret: the Local Cache Key.

## Decision

Session file version 2:

| Field | Content |
|---|---|
| `version` | `2` |
| `device_id` | plain; reused by the next login |
| `identity_url` | plain |
| `lck_encrypted_session` | `{"refresh_token","user_key"}` as a type 2 EncString under the Local Cache Key |

- **Save** needs the Local Cache Key, a refresh token and the user key in memory. Without all three the file is left as it is. So a session is only saved once a PIN is set (an Ephemeral Session saves none).
- **Restore** runs after every successful unlock, whatever the method. After a restart it builds the client, sets the user key and refreshes the access token. After a lock the client is still there and only gets its user key back; no network call is needed.
- **Lock** drops the user key from memory. The tokens stay: they are refreshed while locked, and the notification connection needs them.
- **A failed refresh** deletes the file only when the server refused the token (HTTP 401, or 400 with `invalid_grant`). On a network error the client is kept and the token refresh timer tries again.
- **A version 1 file** is not migrated: nothing in it holds the user key. On the first unlock it is rewritten without its tokens (the device id is kept) and the reply asks for one `sshwarden login`.
- The PIN- and Hello-encrypted token fields, and the code that wrote them, are gone.

## Consequences

- Sync works after a restart with any unlock method, and after lock and unlock.
- The PIN no longer protects the session file directly, so the fixed-salt wrapper is gone.
- **The Local Cache Key now protects more.** Before, it opened the cached SSH keys. Now it also opens the user key, and with the refresh token that is the whole vault, not only the SSH keys. Whatever can recover the Local Cache Key (the PIN, the login keyring, Windows Hello) is worth that much. In multi-device mode the Local Key Cache with its PIN slot lives in a cloud-synced folder, while the session file stays in the per-device folder beside it; a short PIN there is a risk to the whole vault. New PINs therefore need at least 6 characters.
- A user upgrading from version 1 has to run `sshwarden login` once.
- The first unlock after a restart makes one token request. It runs in the daemon's main loop, so a server that does not answer delays other commands by up to 30 seconds, once.
