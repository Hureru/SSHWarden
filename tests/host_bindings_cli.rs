//! Runs the real binary in a throwaway home: `keys bind` / `keys unbind` must
//! change `bindings.json` and the managed snippet every time, not only for the
//! first host (audit 2026-11 item 5, `docs/host-bindings-followup.md` §7).

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("sshwarden-cli-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["home", "data", "local", "run"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(
            root.join("data/config.toml"),
            "[ssh_config]\nmanaged_path = \"sshwarden_config\"\n",
        )
        .unwrap();
        // Only the readable header matters for offline commands.
        std::fs::write(
            root.join("data/local-key-cache.json"),
            r#"{"version":3,"header":{"email":"a@b.c","server_url":"http://127.0.0.1:1","keys":[
                {"name":"Github","vault_item_id":"id-1","public_key_openssh":"ssh-ed25519 AAAA"},
                {"name":"Server","vault_item_id":"id-2","public_key_openssh":"ssh-ed25519 BBBB"}
            ]},"encrypted_payload":"","local_cache_key":{}}"#,
        )
        .unwrap();
        Self { root }
    }

    /// Run `sshwarden <args>` with every path pointed into the sandbox.
    fn run(&self, args: &[&str]) -> std::process::Output {
        let home = self.root.join("home");
        std::process::Command::new(env!("CARGO_BIN_EXE_sshwarden"))
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("SSHWARDEN_HOME", self.root.join("data"))
            .env("SSHWARDEN_LOCAL_HOME", self.root.join("local"))
            .env("SSHWARDEN_RUNTIME_DIR", self.root.join("run"))
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "sshwarden {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn hosts(&self, cipher_id: &str) -> Vec<String> {
        let file = sshwarden_config::bindings::HostBindingsFile::load_from(
            &self.root.join("data/bindings.json"),
        )
        .unwrap();
        file.bindings
            .get(cipher_id)
            .map(|binding| binding.hosts.clone())
            .unwrap_or_default()
    }

    /// The live (uncommented) `Host` lines of the managed snippet.
    fn snippet_host_lines(&self) -> Vec<String> {
        read(&self.root.join("data/sshwarden_config"))
            .lines()
            .filter(|line| line.starts_with("Host "))
            .map(str::to_string)
            .collect()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn bind_and_unbind_change_bindings_and_snippet_every_time() {
    let sandbox = Sandbox::new("bind-unbind");

    sandbox.ok(&["keys", "bind", "Github", "a.example"]);
    assert_eq!(sandbox.hosts("id-1"), ["a.example"]);
    assert_eq!(sandbox.snippet_host_lines(), ["Host a.example"]);

    sandbox.ok(&["keys", "bind", "Github", "b.example"]);
    assert_eq!(sandbox.hosts("id-1"), ["a.example", "b.example"]);
    assert_eq!(sandbox.snippet_host_lines(), ["Host a.example b.example"]);

    sandbox.ok(&["keys", "unbind", "Github", "a.example"]);
    assert_eq!(sandbox.hosts("id-1"), ["b.example"]);
    assert_eq!(sandbox.snippet_host_lines(), ["Host b.example"]);

    sandbox.ok(&["keys", "unbind", "Github", "--all"]);
    assert!(sandbox.hosts("id-1").is_empty());
    assert!(sandbox.snippet_host_lines().is_empty());
}

/// The documented manual route still works: a hand-edited `Host` line in the
/// snippet is imported by the next change instead of being overwritten.
#[test]
fn hand_edited_host_line_survives_the_next_bind() {
    let sandbox = Sandbox::new("hand-edit");
    sandbox.ok(&["keys", "bind", "Github", "a.example"]);

    let snippet_path = sandbox.root.join("data/sshwarden_config");
    let edited = read(&snippet_path).replace("Host a.example", "Host a.example manual.example");
    std::fs::write(&snippet_path, edited).unwrap();

    sandbox.ok(&["keys", "bind", "Server", "c.example"]);
    assert_eq!(sandbox.hosts("id-1"), ["a.example", "manual.example"]);
    assert_eq!(sandbox.hosts("id-2"), ["c.example"]);
}
