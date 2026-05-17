# Linux native unlock defaults to Secret Service

SSHWarden's future Linux native unlock should use Secret Service-compatible desktop keyrings as the default mechanism for protecting the local cache key, with PIN unlock as the fallback when no suitable service is available. Polkit may be considered for authentication prompts or privileged actions, but it is not the default secret storage mechanism because SSHWarden needs to wrap or retrieve a local cache key, not merely authorize an action.
