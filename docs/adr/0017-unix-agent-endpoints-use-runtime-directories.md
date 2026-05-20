# Unix agent endpoints use runtime directories

SSHWarden will place Unix-like SSH agent sockets in per-user runtime locations by default rather than in the user's home directory. This departs from Bitwarden Desktop's documented dotfile socket path but better matches the runtime nature of sockets, supports package-managed installs, and pairs with shell integration that prints the actual endpoint instead of requiring users to memorize it.
