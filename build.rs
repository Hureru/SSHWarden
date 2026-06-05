use std::process::Command;

fn main() {
    let app_version = release_version().unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
    println!("cargo:rustc-env=SSHWARDEN_VERSION={app_version}");
    println!("cargo:rerun-if-env-changed=SSHWARDEN_VERSION");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_TYPE");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    println!("cargo:rerun-if-changed=.git/refs/tags");

    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        // Rebuild resources when manifest/icon changes.
        println!("cargo:rerun-if-changed=app.manifest");
        println!("cargo:rerun-if-changed=crates/sshwarden-ui/assets/sshwarden.ico");

        let mut res = winresource::WindowsResource::new();
        res.set_manifest_file("app.manifest");
        res.set_icon("crates/sshwarden-ui/assets/sshwarden.ico");
        res.set("FileVersion", &app_version);
        res.set("ProductVersion", &app_version);
        res.compile().expect("Failed to compile Windows resources");
    }
}

fn release_version() -> Option<String> {
    if let Ok(version) = std::env::var("SSHWARDEN_VERSION") {
        return normalize_version(&version);
    }

    if std::env::var("GITHUB_REF_TYPE").as_deref() == Ok("tag") {
        if let Ok(tag) = std::env::var("GITHUB_REF_NAME") {
            return normalize_version(&tag);
        }
    }

    let output = Command::new("git")
        .args(["describe", "--tags", "--exact-match", "--match", "v[0-9]*"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let tag = String::from_utf8(output.stdout).ok()?;
    normalize_version(&tag)
}

fn normalize_version(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let version = trimmed.strip_prefix('v').unwrap_or(trimmed);

    if is_semver_like(version) {
        Some(version.to_owned())
    } else {
        None
    }
}

fn is_semver_like(version: &str) -> bool {
    let core_end = version.find(['-', '+']).unwrap_or(version.len());
    let core = &version[..core_end];
    let suffix = &version[core_end..];

    let mut parts = core.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };

    parts.next().is_none()
        && [major, minor, patch].iter().all(|part| is_numeric(part))
        && valid_suffix(suffix)
}

fn is_numeric(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_suffix(value: &str) -> bool {
    value.is_empty()
        || (value.len() > 1
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'+' | b'.')))
}
