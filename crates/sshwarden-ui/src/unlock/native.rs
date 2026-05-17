use anyhow::{anyhow, Result};

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub fn native_available() -> bool {
        which_security().is_some()
    }

    pub fn native_encrypt_local_cache_key(encoded_local_cache_key: &str) -> Result<String> {
        let security =
            which_security().ok_or_else(|| anyhow!("macOS security command not found"))?;
        let status = std::process::Command::new(&security)
            .args([
                "add-generic-password",
                "-a",
                "SSHWarden",
                "-s",
                "works.earendil.sshwarden.local-cache-key",
                "-w",
                encoded_local_cache_key,
                "-U",
            ])
            .status()?;
        if !status.success() {
            return Err(anyhow!("security add-generic-password failed"));
        }
        Ok("keychain:works.earendil.sshwarden.local-cache-key".to_string())
    }

    pub fn native_decrypt_local_cache_key(_slot: &str) -> Result<String> {
        let security =
            which_security().ok_or_else(|| anyhow!("macOS security command not found"))?;
        let output = std::process::Command::new(&security)
            .args([
                "find-generic-password",
                "-a",
                "SSHWarden",
                "-s",
                "works.earendil.sshwarden.local-cache-key",
                "-w",
            ])
            .output()?;
        if !output.status.success() {
            return Err(anyhow!("security find-generic-password failed"));
        }
        Ok(String::from_utf8(output.stdout)?.trim_end().to_string())
    }

    pub fn native_delete_local_cache_key(_slot: Option<&str>) -> Result<()> {
        let Some(security) = which_security() else {
            return Ok(());
        };
        let _ = std::process::Command::new(&security)
            .args([
                "delete-generic-password",
                "-a",
                "SSHWarden",
                "-s",
                "works.earendil.sshwarden.local-cache-key",
            ])
            .status();
        Ok(())
    }

    fn which_security() -> Option<String> {
        ["/usr/bin/security", "security"]
            .into_iter()
            .find(|cmd| std::process::Command::new(cmd).arg("-h").output().is_ok())
            .map(ToOwned::to_owned)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub fn native_available() -> bool {
        which_secret_tool().is_some()
    }

    pub fn native_encrypt_local_cache_key(encoded_local_cache_key: &str) -> Result<String> {
        let secret_tool = which_secret_tool().ok_or_else(|| anyhow!("secret-tool not found"))?;
        let mut child = std::process::Command::new(&secret_tool)
            .args([
                "store",
                "--label=SSHWarden Local Cache Key",
                "application",
                "sshwarden",
                "kind",
                "local-cache-key",
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        {
            use std::io::Write;
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| anyhow!("secret-tool stdin unavailable"))?;
            stdin.write_all(encoded_local_cache_key.as_bytes())?;
        }
        let status = child.wait()?;
        if !status.success() {
            return Err(anyhow!("secret-tool store failed"));
        }
        Ok("secret-service:application=sshwarden;kind=local-cache-key".to_string())
    }

    pub fn native_decrypt_local_cache_key(_slot: &str) -> Result<String> {
        let secret_tool = which_secret_tool().ok_or_else(|| anyhow!("secret-tool not found"))?;
        let output = std::process::Command::new(&secret_tool)
            .args([
                "lookup",
                "application",
                "sshwarden",
                "kind",
                "local-cache-key",
            ])
            .output()?;
        if !output.status.success() {
            return Err(anyhow!("secret-tool lookup failed"));
        }
        Ok(String::from_utf8(output.stdout)?.trim_end().to_string())
    }

    pub fn native_delete_local_cache_key(_slot: Option<&str>) -> Result<()> {
        let Some(secret_tool) = which_secret_tool() else {
            return Ok(());
        };
        let _ = std::process::Command::new(&secret_tool)
            .args([
                "clear",
                "application",
                "sshwarden",
                "kind",
                "local-cache-key",
            ])
            .status();
        Ok(())
    }

    fn which_secret_tool() -> Option<String> {
        ["secret-tool", "/usr/bin/secret-tool"]
            .into_iter()
            .find(|cmd| {
                std::process::Command::new(cmd)
                    .arg("--version")
                    .output()
                    .is_ok()
            })
            .map(ToOwned::to_owned)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;

    pub fn native_available() -> bool {
        false
    }

    pub fn native_encrypt_local_cache_key(_encoded_local_cache_key: &str) -> Result<String> {
        Err(anyhow!("native unlock is not available on this platform"))
    }

    pub fn native_decrypt_local_cache_key(_slot: &str) -> Result<String> {
        Err(anyhow!("native unlock is not available on this platform"))
    }

    pub fn native_delete_local_cache_key(_slot: Option<&str>) -> Result<()> {
        Ok(())
    }
}

pub use platform::{
    native_available, native_decrypt_local_cache_key, native_delete_local_cache_key,
    native_encrypt_local_cache_key,
};
