//! DUID-LLT generation and on-disk persistence (RFC 8415 §11.2).

use eui48::MacAddress;
use std::io::{self, Read, Write};
use std::path::Path;
use thiserror::Error;

const DUID_TYPE_LLT: u16 = 1;
const HW_TYPE_ETHERNET: u16 = 1;
// 2000-01-01 00:00:00 UTC, as Unix timestamp.
const DUID_TIME_EPOCH: u64 = 946_684_800;

#[derive(Debug, Error)]
pub enum DuidError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("DUID file is corrupt or unsupported length: {0}")]
    Corrupt(usize),
}

/// Load the DUID at `path`, or generate a new DUID-LLT (and persist it) if
/// the file does not exist.
pub fn load_or_generate(path: &Path, mac: MacAddress) -> Result<Vec<u8>, DuidError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    match std::fs::File::open(path) {
        Ok(mut f) => {
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            if buf.len() < 2 {
                return Err(DuidError::Corrupt(buf.len()));
            }
            Ok(buf)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let duid = generate_llt(mac);
            // Race-safe write: create with O_CREAT|O_EXCL, falling back to a
            // re-read if a concurrent writer beat us to it.
            let tmp_path = path.with_extension("tmp");
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            match opts.open(&tmp_path) {
                Ok(mut f) => {
                    f.write_all(&duid)?;
                    f.sync_all()?;
                    drop(f);
                    std::fs::rename(&tmp_path, path)?;
                    Ok(duid)
                }
                Err(e2) if e2.kind() == io::ErrorKind::AlreadyExists => {
                    // Another writer is in flight; read whatever they wrote.
                    let mut f = std::fs::File::open(path)?;
                    let mut buf = Vec::new();
                    f.read_to_end(&mut buf)?;
                    Ok(buf)
                }
                Err(e2) => Err(e2.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// Build a fresh DUID-LLT. Total 14 bytes.
pub fn generate_llt(mac: MacAddress) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(DUID_TIME_EPOCH);
    let time = now.saturating_sub(DUID_TIME_EPOCH) as u32;

    let mut duid = Vec::with_capacity(14);
    duid.extend_from_slice(&DUID_TYPE_LLT.to_be_bytes());
    duid.extend_from_slice(&HW_TYPE_ETHERNET.to_be_bytes());
    duid.extend_from_slice(&time.to_be_bytes());
    duid.extend_from_slice(mac.as_bytes());
    duid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_llt_layout() {
        let mac = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let duid = generate_llt(mac);
        assert_eq!(duid.len(), 14);
        assert_eq!(&duid[0..2], &[0, 1]);
        assert_eq!(&duid[2..4], &[0, 1]);
        assert_eq!(&duid[8..14], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn round_trip_disk() {
        let mac = MacAddress::new([1, 2, 3, 4, 5, 6]);
        let dir = std::env::temp_dir().join(format!("rust-dhcp-duid-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("duid");
        let _ = std::fs::remove_file(&path);

        let first = load_or_generate(&path, mac).unwrap();
        let second = load_or_generate(&path, mac).unwrap();
        assert_eq!(first, second);
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
