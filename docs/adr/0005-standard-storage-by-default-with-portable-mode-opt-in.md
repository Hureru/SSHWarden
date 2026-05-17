# Standard storage by default with portable mode opt-in

SSHWarden will use each supported platform's standard per-user storage locations by default rather than writing user data beside the executable. Portable mode remains supported as an explicit user choice, because executable-adjacent storage works for portable Windows zip distributions but conflicts with Linux package installs, macOS application bundles, multi-user systems, runtime socket placement, and platform expectations for private user data.
