//! Size-based rotation for the daemon log file.
//!
//! The daemon writes logs beside itself only in background mode; a long-running
//! agent would otherwise grow that file without bound (and, before machine-local
//! state moved out of the shared data root, a cloud-synced install would upload
//! it forever). One backup is kept: `sshwarden.log` + `sshwarden.log.1`.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Append-only log writer that rotates to a single `<log>.1` backup once the
/// current file would exceed `max_bytes`. `max_bytes == 0` disables rotation.
pub(crate) struct RotatingFileWriter {
    path: PathBuf,
    file: File,
    max_bytes: u64,
    /// Bytes written to the current file (seeded from its size at open).
    written: u64,
    /// Set after a failed rotation so the warning is emitted once, not once per
    /// log record.
    rotation_warned: bool,
}

impl RotatingFileWriter {
    /// Open (creating if needed) `path` for appending with size-based rotation.
    pub(crate) fn open(path: &Path, max_bytes: u64) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
        Ok(Self {
            path: path.to_path_buf(),
            file,
            max_bytes,
            written,
            rotation_warned: false,
        })
    }

    fn should_rotate(&self, incoming: usize) -> bool {
        // Never rotate an empty file (that would spin on a cap below one record)
        // and never rotate when rotation is disabled.
        self.max_bytes > 0
            && self.written > 0
            && self.written.saturating_add(incoming as u64) > self.max_bytes
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        let backup = backup_path(&self.path);
        match std::fs::remove_file(&backup) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        std::fs::rename(&self.path, &backup)?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        self.rotation_warned = false;
        Ok(())
    }

    /// Rotate if needed, tolerating failure: a rotation that cannot complete
    /// (cloud-sync or antivirus holding the file) must never drop log output or
    /// take the daemon down, so we warn once and keep appending.
    #[allow(clippy::print_stderr)]
    fn rotate_if_needed(&mut self, incoming: usize) {
        if !self.should_rotate(incoming) {
            return;
        }
        if let Err(e) = self.rotate() {
            if !self.rotation_warned {
                eprintln!(
                    "sshwarden: log rotation failed ({e}); continuing to append to {}",
                    self.path.display()
                );
                self.rotation_warned = true;
            }
        }
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.rotate_if_needed(buf.len());
        let written = self.file.write(buf)?;
        self.written = self.written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// `sshwarden.log` -> `sshwarden.log.1` (extension preserved, unlike
/// [`Path::with_extension`]).
fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sshwarden-logging-test-{}-{unique}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rotates_to_single_backup_past_the_cap() {
        let dir = temp_dir("rotate");
        let path = dir.join("sshwarden.log");
        let mut writer = RotatingFileWriter::open(&path, 32).unwrap();

        writer.write_all(b"first-record\n").unwrap(); // 13 bytes
        assert!(!dir.join("sshwarden.log.1").exists());

        writer.write_all(b"second-record\n").unwrap(); // would reach 26 bytes
        assert!(!dir.join("sshwarden.log.1").exists());

        writer.write_all(b"third-record\n").unwrap(); // 39 > 32 -> rotate first
        writer.flush().unwrap();

        let backup = std::fs::read_to_string(dir.join("sshwarden.log.1")).unwrap();
        assert_eq!(backup, "first-record\nsecond-record\n");
        let current = std::fs::read_to_string(&path).unwrap();
        assert_eq!(current, "third-record\n");
    }

    #[test]
    fn keeps_only_one_backup_over_repeated_rotations() {
        let dir = temp_dir("single-backup");
        let path = dir.join("sshwarden.log");
        let mut writer = RotatingFileWriter::open(&path, 8).unwrap();

        for _ in 0..5 {
            writer.write_all(b"record-a\n").unwrap();
            writer.flush().unwrap();
        }

        let backup = std::fs::read_to_string(dir.join("sshwarden.log.1")).unwrap();
        assert_eq!(backup, "record-a\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "record-a\n");
        // No `.2` is ever produced.
        assert!(!dir.join("sshwarden.log.1.1").exists());
    }

    #[test]
    fn resumes_size_accounting_for_an_existing_file() {
        let dir = temp_dir("resume");
        let path = dir.join("sshwarden.log");
        std::fs::write(&path, "existing-content\n").unwrap();

        let mut writer = RotatingFileWriter::open(&path, 24).unwrap();
        writer.write_all(b"more\n").unwrap(); // 17 + 5 = 22, still under the cap
        writer.flush().unwrap();
        assert!(!dir.join("sshwarden.log.1").exists());

        writer.write_all(b"and-more\n").unwrap(); // 22 + 9 > 24 -> rotate
        writer.flush().unwrap();
        assert!(dir.join("sshwarden.log.1").exists());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "and-more\n",
            "the rotation must not drop the record that triggered it"
        );
    }

    #[test]
    fn zero_cap_disables_rotation() {
        let dir = temp_dir("disabled");
        let path = dir.join("sshwarden.log");
        let mut writer = RotatingFileWriter::open(&path, 0).unwrap();

        for _ in 0..100 {
            writer.write_all(b"0123456789\n").unwrap();
        }
        writer.flush().unwrap();

        assert!(!dir.join("sshwarden.log.1").exists());
        assert_eq!(std::fs::read_to_string(&path).unwrap().len(), 1100);
    }

    #[test]
    fn backup_preserves_the_log_extension() {
        assert_eq!(
            backup_path(Path::new("/tmp/sshwarden.log")),
            PathBuf::from("/tmp/sshwarden.log.1")
        );
    }
}
