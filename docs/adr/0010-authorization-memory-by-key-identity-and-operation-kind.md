# Authorization memory by vault item and operation kind

SSHWarden's RememberUntilLock behavior will remember approval by Vault Item Id and operation kind rather than by process or display name. Agent forwarding requests will always require explicit approval, and authorization memory is cleared on lock, account/session boundary, forget, daemon restart, deletion/archive, or key material change for that item; using the Vault Item Id keeps approvals stable across key renames while still requiring fresh approval after key rotation.
