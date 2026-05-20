# Remembered device starts locked with listable key identities

A remembered device will start in the locked state without prompting for unlock, while still allowing SSH clients to list key identities from local metadata. This aligns SSHWarden with SSH agent discovery patterns and Bitwarden Desktop V2 behavior while preserving the lock boundary: private signing material and local cache refresh capability are unavailable until explicit unlock.
