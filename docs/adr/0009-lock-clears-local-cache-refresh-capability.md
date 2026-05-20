# Lock clears local cache refresh capability

SSHWarden lock will clear both usable SSH private keys and the in-memory local cache key, so a locked daemon cannot refresh the local key cache in the background. This favors a simple security promise for lock over convenience: after lock, SSH keys and the capability to rewrite the encrypted local key cache only return after an explicit unlock or login.
