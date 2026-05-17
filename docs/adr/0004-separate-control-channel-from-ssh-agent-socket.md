# Separate control channel from SSH agent socket

SSHWarden will keep daemon control commands on a dedicated local control channel instead of extending or overloading the SSH agent socket. Windows will continue to use a named pipe, while Linux and macOS should use a Unix domain socket that carries the same JSON control protocol, preserving a clear boundary between SSH client requests and user control of daemon state.
