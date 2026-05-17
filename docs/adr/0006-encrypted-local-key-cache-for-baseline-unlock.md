# Encrypted local key cache for baseline unlock

SSHWarden's baseline experience will store previously synced SSH keys in an encrypted local key cache so users can unlock and use SSH keys after daemon restart without contacting Bitwarden. This deliberately favors reliable offline agent usability over a design that stores only session material and requires a fresh sync before keys can be used; user-facing language should distinguish this local key cache from the Bitwarden vault.
