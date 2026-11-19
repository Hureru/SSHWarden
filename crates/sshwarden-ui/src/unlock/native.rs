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

    pub fn native_slot_is_legacy(_slot: &str) -> bool {
        false
    }

    pub fn native_encrypt_local_cache_key(
        encoded_local_cache_key: &str,
        _previous_slot: Option<&str>,
    ) -> Result<String> {
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

    /// The entry every copy of SSHWarden shared before each got its own.
    const LEGACY_ATTRS: [&str; 4] = ["application", "sshwarden", "kind", "local-cache-key"];

    /// The id of the keyring entry a slot text points to; `None` for a slot
    /// written before entries had one.
    fn slot_instance(slot: &str) -> Option<&str> {
        slot.split(';')
            .find_map(|part| part.strip_prefix("instance="))
            .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit()))
    }

    /// The keyring attributes of a slot's entry. `secret-tool` matches every
    /// entry that has the given attributes, so the per-instance entries use
    /// another `kind`: a lookup or clear of the shared entry must not hit them.
    fn slot_attrs(slot: &str) -> Vec<&str> {
        match slot_instance(slot) {
            Some(id) => vec![
                "application",
                "sshwarden",
                "kind",
                "instance-local-cache-key",
                "instance",
                id,
            ],
            None => LEGACY_ATTRS.to_vec(),
        }
    }

    pub fn native_slot_is_legacy(slot: &str) -> bool {
        slot_instance(slot).is_none()
    }

    /// Stores the key in this instance's own keyring entry: the one
    /// `previous_slot` names, or a new one with a random id. One shared entry
    /// let a second copy (a dev build, another `SSHWARDEN_HOME`) overwrite or
    /// delete the key of the first.
    pub fn native_encrypt_local_cache_key(
        encoded_local_cache_key: &str,
        previous_slot: Option<&str>,
    ) -> Result<String> {
        let secret_tool = which_secret_tool().ok_or_else(|| anyhow!("secret-tool not found"))?;
        let slot = match previous_slot.and_then(slot_instance) {
            Some(id) => slot_text(id),
            None => {
                use std::io::Read;
                let mut id = [0u8; 8];
                std::fs::File::open("/dev/urandom")?.read_exact(&mut id)?;
                slot_text(&id.iter().map(|b| format!("{b:02x}")).collect::<String>())
            }
        };
        let mut child = std::process::Command::new(&secret_tool)
            .args(["store", "--label=SSHWarden Local Cache Key"])
            .args(slot_attrs(&slot))
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
        Ok(slot)
    }

    fn slot_text(id: &str) -> String {
        format!("secret-service:application=sshwarden;kind=instance-local-cache-key;instance={id}")
    }

    pub fn native_decrypt_local_cache_key(slot: &str) -> Result<String> {
        let secret_tool = which_secret_tool().ok_or_else(|| anyhow!("secret-tool not found"))?;
        let output = std::process::Command::new(&secret_tool)
            .arg("lookup")
            .args(slot_attrs(slot))
            .output()?;
        if !output.status.success() {
            return Err(anyhow!("secret-tool lookup failed"));
        }
        Ok(String::from_utf8(output.stdout)?.trim_end().to_string())
    }

    pub fn native_delete_local_cache_key(slot: Option<&str>) -> Result<()> {
        // No slot: this instance stored nothing. The shared entry of older
        // versions may belong to another copy, so it is left alone.
        let Some(slot) = slot else {
            return Ok(());
        };
        let Some(secret_tool) = which_secret_tool() else {
            // No keyring tool present — nothing was stored, nothing to delete.
            return Ok(());
        };
        // XP-5: check the exit status so a failed revocation is reported (and
        // surfaced by `forget`) instead of silently claiming success.
        let status = std::process::Command::new(&secret_tool)
            .arg("clear")
            .args(slot_attrs(slot))
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_slot_with_an_id_gets_its_own_entry_and_an_old_slot_the_shared_one() {
            let old = "secret-service:application=sshwarden;kind=local-cache-key";
            assert!(native_slot_is_legacy(old));
            assert_eq!(slot_attrs(old), LEGACY_ATTRS);

            let own = slot_text("0a1b2c3d4e5f6071");
            assert!(!native_slot_is_legacy(&own));
            let attrs = slot_attrs(&own);
            assert_eq!(attrs[4..], ["instance", "0a1b2c3d4e5f6071"]);
            // Disjoint from the shared entry, or a clear of one would take both.
            assert_ne!(attrs[3], LEGACY_ATTRS[3]);

            // An id from a file is passed to a command: letters and digits only.
            assert!(native_slot_is_legacy("secret-service:kind=x;instance=a b"));
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;

    pub fn native_available() -> bool {
        false
    }

    pub fn native_slot_is_legacy(_slot: &str) -> bool {
        false
    }

    pub fn native_encrypt_local_cache_key(
        _encoded_local_cache_key: &str,
        _previous_slot: Option<&str>,
    ) -> Result<String> {
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
    native_encrypt_local_cache_key, native_slot_is_legacy,
};
