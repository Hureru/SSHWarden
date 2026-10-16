//! End-to-end exercise of the host-binding storage + SSH-config include
//! plumbing: bind hosts, persist, reload from disk, prune orphans, and render
//! the managed `Include` line. Everything uses explicit temp paths, so the test
//! is independent of `SSHWARDEN_HOME` and safe to run in parallel.
#![allow(clippy::unwrap_used)]

use sshwarden_config::bindings::HostBindingsFile;
use sshwarden_config::ssh_config::{
    include_line_with_style, line_matches_sshwarden_include, SSHWARDEN_INCLUDE_MARKER,
};
use sshwarden_config::SshConfigPathStyle;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "sshwarden-bindings-it-{}-{unique}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn bindings_round_trip_prune_and_include_line() {
    let dir = temp_dir("round-trip");
    let path = dir.join("host_bindings.json");

    // add_host → save_to → load_from preserves every host in order.
    let mut bindings = HostBindingsFile::default();
    bindings.add_host("id-1", "github.com").unwrap();
    bindings.add_host("id-1", "gitlab.com").unwrap();
    bindings.add_host("id-2", "example.com").unwrap();
    bindings.save_to(&path).unwrap();

    let reloaded = HostBindingsFile::load_from(&path).unwrap();
    assert_eq!(
        reloaded.bindings.get("id-1").unwrap().hosts,
        vec!["github.com".to_string(), "gitlab.com".to_string()]
    );
    assert_eq!(
        reloaded.bindings.get("id-2").unwrap().hosts,
        vec!["example.com".to_string()]
    );

    // Pruning against the surviving key set drops the orphaned binding only.
    let mut pruned = reloaded;
    let removed = pruned.prune_orphans(["id-1"]);
    assert_eq!(removed, 1);
    assert!(pruned.bindings.contains_key("id-1"));
    assert!(!pruned.bindings.contains_key("id-2"));

    // The managed Include line is written and recognised via its match helper.
    let managed = dir.join("sshwarden_config");
    let line = include_line_with_style(&managed, SshConfigPathStyle::Absolute);
    assert!(SSHWARDEN_INCLUDE_MARKER.contains("SSHWarden"));
    assert!(line.starts_with("Include "));
    assert!(line_matches_sshwarden_include(&line, &managed));

    let _ = std::fs::remove_dir_all(dir);
}
