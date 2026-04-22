use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub struct ArtifactConfig {
    pub tx_folder: PathBuf,
    pub rx_folder: PathBuf,
    pub failed_folder: PathBuf,
    pub archive_folder: PathBuf,
    pub s2c_groups: Vec<&'static str>,
    pub c2s_groups: Vec<&'static str>,
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
                s2c_groups: vec!["binaries", "wasm"],
                c2s_groups: vec!["logs"],
            }
        })
    }
}
