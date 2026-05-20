# Explicit agent takeover without agent chaining

On Unix-like platforms, SSHWarden shell integration will explicitly make SSHWarden the active SSH agent for that shell or session rather than transparently proxying to any previously configured agent. Agent chaining is intentionally out of scope for the baseline experience because it creates ambiguous security semantics around key listing, signing authorization, locking, and which agent owns each key.
