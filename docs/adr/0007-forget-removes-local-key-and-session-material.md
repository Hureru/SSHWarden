# Forget removes local key and session material

SSHWarden will distinguish locking from forgetting: lock only makes remembered SSH keys temporarily unusable, while forget removes local key cache, device session material, platform unlock enrollment, and in-memory keys so the device must log in to Bitwarden again before using SSH keys. Forget intentionally does not remove user preferences, installation state, shell integration, or logs because it is a security boundary for remembered secrets rather than an uninstall or reset operation.
