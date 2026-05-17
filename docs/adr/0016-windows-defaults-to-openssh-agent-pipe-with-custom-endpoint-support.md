# Windows defaults to OpenSSH agent pipe with custom endpoint support

SSHWarden will default to the standard Windows OpenSSH agent named pipe so existing Windows SSH and Git tooling works without per-tool configuration, matching Bitwarden Desktop's integration model. A custom agent endpoint remains supported for users who cannot or do not want to disable another agent occupying the default pipe.
