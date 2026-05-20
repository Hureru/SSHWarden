# Core capability parity with platform-native unlock

SSHWarden will require core user-facing capabilities to work on every supported platform: Bitwarden login and sync, local SSH agent operation, lock and unlock, PIN unlock, signing authorization, CLI control commands, auto-lock, local encrypted cache, startup integration, and diagnostics. Platform-native unlock methods may differ by operating system, because Windows Hello, macOS Touch ID/Keychain, and Linux desktop secret or policy services expose different primitives while serving the same user goal.
