# Envelope encryption for refreshable local key cache

SSHWarden will evolve the local key cache from direct PIN-or-platform encryption of SSH keys to envelope encryption: a local cache key encrypts the cached SSH keys, while PIN and platform unlock methods unlock or wrap that cache key. This keeps the Bitwarden vault as the source of truth, allows the daemon to refresh the local key cache after successful sync without retaining the user's PIN, and gives Windows Hello, future macOS Touch ID/Keychain, and future Linux native unlock methods the same role in the model.
