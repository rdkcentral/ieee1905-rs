use crate::fs_quota_aware_storage::FsQuotaAwareStorage;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

////////////////////////////////////////////////////////////////////////////////
pub struct ArtifactConfig {
    pub tx_folder: PathBuf,
    pub rx_folder: PathBuf,
    pub failed_folder: PathBuf,
    pub archive_folder: PathBuf,
    pub s2c_artifact_types: Vec<&'static str>,
    pub c2s_artifact_types: Vec<&'static str>,
}

impl ArtifactConfig {
    pub const PORT: u16 = 6666;

    pub fn get() -> &'static Self {
        static CELL: OnceLock<ArtifactConfig> = OnceLock::new();
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
pub struct ArtifactFilter {
    pub mac: String,
}

////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactInfo {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub ts_secs: u64,
}

////////////////////////////////////////////////////////////////////////////////
pub fn is_file_name_sanitized(name: impl AsRef<Path>) -> bool {
    let mut components = name.as_ref().components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None),
    )
}
