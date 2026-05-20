# macOS native unlock uses Keychain with user presence

SSHWarden's future macOS native unlock will protect access to the local cache key through Keychain access control requiring user presence, such as Touch ID or system password fallback. Keychain alone would store the secret but would not provide the same explicit unlock ceremony as Windows Hello, while Touch ID alone is not a storage mechanism.
