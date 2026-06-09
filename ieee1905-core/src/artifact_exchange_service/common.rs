use crate::artifact_exchange_service::fs_quota_aware_storage::FsQuotaAwareStorage;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::OnceLock;

////////////////////////////////////////////////////////////////////////////////
pub struct ArtifactExchangeConfig {
    pub tx_folder: PathBuf,
    pub rx_folder: PathBuf,
    pub failed_folder: PathBuf,
    pub archive_folder: PathBuf,
    pub s2c_artifact_types: Vec<&'static str>,
    pub c2s_artifact_types: Vec<&'static str>,
}

impl ArtifactExchangeConfig {
    pub const PORT: u16 = 6666;

    pub fn get() -> &'static Self {
        static CELL: OnceLock<ArtifactExchangeConfig> = OnceLock::new();
        CELL.get_or_init(|| {
            let base_folder = Path::new("/tmp/artifacts/");
            Self {
                tx_folder: base_folder.join("tx"),
                rx_folder: base_folder.join("rx"),
                failed_folder: base_folder.join("failed"),
                archive_folder: base_folder.join("archive"),
                s2c_artifact_types: vec!["binaries", "wasm"],
                c2s_artifact_types: vec!["logs"],
            }
        })
    }

    pub fn get_tx_archive_storage(&self, kind: &str) -> FsQuotaAwareStorage {
        FsQuotaAwareStorage::new(
            self.archive_folder.join("tx").join(kind),
            64,
            32 * 1024 * 1024,
        )
    }

    pub fn get_tx_failure_storage(&self, kind: &str) -> FsQuotaAwareStorage {
        FsQuotaAwareStorage::new(
            self.failed_folder.join("tx").join(kind),
            16,
            8 * 1024 * 1024,
        )
    }

    pub fn get_rx_archive_storage(&self, kind: &str) -> FsQuotaAwareStorage {
        FsQuotaAwareStorage::new(
            self.archive_folder.join("rx").join(kind),
            64,
            32 * 1024 * 1024,
        )
    }

    pub fn get_rx_failure_storage(&self, kind: &str) -> FsQuotaAwareStorage {
        FsQuotaAwareStorage::new(
            self.failed_folder.join("rx").join(kind),
            16,
            8 * 1024 * 1024,
        )
    }
}

////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactExchangeFilter {
    pub mac: String,
}

////////////////////////////////////////////////////////////////////////////////
pub fn format_mac_as_file_prefix(mac: MacAddr) -> String {
    format!(
        "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5,
    )
}

////////////////////////////////////////////////////////////////////////////////
pub fn parse_mac_as_file_prefix(value: &str) -> Option<MacAddr> {
    let value = value.replace('-', ":");
    MacAddr::from_str(&value).ok()
}

////////////////////////////////////////////////////////////////////////////////
pub fn is_file_name_sanitized(name: impl AsRef<Path>) -> bool {
    let mut components = name.as_ref().components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None),
    )
}

////////////////////////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_file_name_sanitized() {
        assert!(is_file_name_sanitized("artifact.bin"));
        assert!(is_file_name_sanitized("logs.tar.gz"));
        assert!(is_file_name_sanitized("with-dashes_and.dots"));
        assert!(is_file_name_sanitized("binaries"));

        assert!(!is_file_name_sanitized(""));
        assert!(!is_file_name_sanitized("."));
        assert!(!is_file_name_sanitized(".."));
        assert!(!is_file_name_sanitized("/etc/passwd"));
        assert!(!is_file_name_sanitized("a/b"));
        assert!(!is_file_name_sanitized("../secret"));
        assert!(!is_file_name_sanitized("foo/../bar"));
        assert!(!is_file_name_sanitized("dir/sub/file"));
    }

    #[test]
    fn test_format_mac_as_file_prefix_uses_lowercase_dashes() {
        let mac = MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        assert_eq!(format_mac_as_file_prefix(mac), "aa-bb-cc-dd-ee-ff");
    }

    #[test]
    fn test_format_mac_as_file_prefix_zero_pads_each_octet() {
        let mac = MacAddr(0x01, 0x02, 0x03, 0x00, 0x0a, 0x0f);
        assert_eq!(format_mac_as_file_prefix(mac), "01-02-03-00-0a-0f");
    }
}
