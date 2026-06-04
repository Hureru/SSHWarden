#[cfg(not(target_os = "macos"))]
use anyhow::anyhow;
use anyhow::Result;

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    const SERVICE: &str = "works.earendil.sshwarden.local-cache-key";
    const ACCOUNT: &str = "SSHWarden";

    pub fn native_available() -> bool {
        // XP-2: the macOS path reads/writes the login Keychain with no
        // user-presence ceremony (Touch ID / password), which does not satisfy
        // ADR-0015. Until a SecAccessControl (kSecAccessControlUserPresence) +
        // LAContext ceremony is implemented and verified on real hardware,
        // disable native unlock so SSHWarden falls back to PIN/password instead
        // of silently using the Keychain.
        // TODO(XP-2): implement the user-presence ceremony, then return true.
        false
    }

    pub fn native_encrypt_local_cache_key(encoded_local_cache_key: &str) -> Result<String> {
        security_framework::passwords::set_generic_password(
            SERVICE,
            ACCOUNT,
            encoded_local_cache_key.as_bytes(),
        )?;
        Ok(format!("keychain:{SERVICE}"))
    }

    pub fn native_decrypt_local_cache_key(_slot: &str) -> Result<String> {
        let bytes = security_framework::passwords::get_generic_password(SERVICE, ACCOUNT)?;
        Ok(String::from_utf8(bytes)?.trim_end().to_string())
    }

    pub fn native_delete_local_cache_key(_slot: Option<&str>) -> Result<()> {
        match security_framework::passwords::delete_generic_password(SERVICE, ACCOUNT) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == -25300 => Ok(()), // errSecItemNotFound
            Err(e) => Err(e.into()),
        }
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
            // No keyring tool present — nothing was stored, nothing to delete.
            return Ok(());
        };
        // XP-5: check the exit status so a failed revocation is reported (and
        // surfaced by `forget`) instead of silently claiming success.
        let status = std::process::Command::new(&secret_tool)
            .args([
                "clear",
                "application",
                "sshwarden",
                "kind",
                "local-cache-key",
            ])
            .status()
            .map_err(|e| anyhow!("secret-tool clear failed to run: {e}"))?;
        if !status.success() {
            return Err(anyhow!(
                "secret-tool clear exited unsuccessfully; native unlock material may remain in the keyring"
            ));
        }
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
