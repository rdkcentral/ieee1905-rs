use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::bail;
use tracing::{error, info};

////////////////////////////////////////////////////////////////////////////////
pub struct FsQuotaAwareStorage {
    dir: PathBuf,
    max_files_count: usize,
    max_total_size: u64,
}

////////////////////////////////////////////////////////////////////////////////
struct FileInfo {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

impl FsQuotaAwareStorage {
    ////////////////////////////////////////////////////////////////////////////////
    pub fn new(dir: impl Into<PathBuf>, max_files_count: usize, max_total_size: u64) -> Self {
        Self {
            dir: dir.into(),
            max_files_count,
            max_total_size,
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    pub async fn store(&mut self, file: impl AsRef<Path>) -> anyhow::Result<()> {
        let source_file = tokio::fs::canonicalize(file).await?;
        let Some(source_file_name) = source_file.file_name() else {
            bail!("{source_file:?} is empty");
        };

        let metadata = tokio::fs::metadata(&source_file).await?;
        if !metadata.is_file() {
            bail!("{source_file:?} is not a file");
        }

        let source_file_size = metadata.size();
        if source_file_size > self.max_total_size {
            bail!("{source_file:?} is too large: {source_file_size}");
        }

        if let Err(e) = tokio::fs::create_dir_all(&self.dir).await {
            bail!("failed to create target directory {:?}: {e}", self.dir);
        }
        if let Err(e) = self.enforce_quota(metadata.size()).await {
            bail!("failed to enforce quota: {e}");
        }

        let target_file = self.dir.join(&source_file_name);
        info!(src = ?source_file, dst = ?target_file, "moving file");
        tokio::fs::rename(source_file, target_file).await?;

        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn enforce_quota(&mut self, extra_size: u64) -> anyhow::Result<()> {
        let max_total_size = self.max_total_size.saturating_sub(extra_size);
        let max_files_count = self.max_files_count.saturating_sub((extra_size > 0).into());

        let mut current_files = self.collect_files().await?;
        let mut current_size = current_files.iter().map(|e| e.size).sum::<u64>();
        current_files.sort_by(|a, b| b.modified.cmp(&a.modified));

        while (current_size > max_total_size || current_files.len() > max_files_count)
            && let Some(file_to_remove) = current_files.pop()
        {
            match tokio::fs::remove_file(&file_to_remove.path).await {
                Ok(_) => current_size = current_size.saturating_sub(file_to_remove.size),
                Err(e) => error!("failed to remove {:?} file: {e}", file_to_remove.path),
            }
        }
        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn collect_files(&mut self) -> anyhow::Result<Vec<FileInfo>> {
        let mut iterator = tokio::fs::read_dir(&self.dir).await?;
        let mut result = Vec::new();

        while let Ok(Some(entry)) = iterator.next_entry().await {
            let Ok(metadata) = entry.metadata().await else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            result.push(FileInfo {
                path: entry.path(),
                size: metadata.size(),
                modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, time::Duration};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_store_single_file() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let source_dir = temp_dir.path().join("source");
        let target_dir = temp_dir.path().join("target");
        let source_path = create_file_in(&source_dir, "test.txt", b"some test data");

        let mut storage = FsQuotaAwareStorage::new(&target_dir, 10, 1024);
        storage.store(&source_path).await?;

        let stored_files = collect_files(&target_dir)?;
        assert_eq!(stored_files.len(), 1);
        assert_eq!(stored_files[0], "test.txt");

        Ok(())
    }

    #[tokio::test]
    async fn test_store_nonexistent_file_fails() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let target_dir = temp_dir.path().join("target");
        let nonexistent = PathBuf::from("/nonexistent/file.txt");

        let mut storage = FsQuotaAwareStorage::new(&target_dir, 10, 1024);
        let result = storage.store(&nonexistent).await;
        assert!(result.is_err());

        let stored_files = collect_files(&target_dir)?;
        assert!(stored_files.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_store_directory_fails() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let source_dir = temp_dir.path().join("source");
        let target_dir = temp_dir.path().join("target");

        let mut storage = FsQuotaAwareStorage::new(&target_dir, 10, 1024);
        let result = storage.store(&source_dir).await;
        assert!(result.is_err());

        let stored_files = collect_files(&target_dir)?;
        assert!(stored_files.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_enforce_quota_by_size() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let source_dir = temp_dir.path().join("source");
        let target_dir = temp_dir.path().join("target");

        // Create a file larger than the quota
        let source_path = create_file_in(&source_dir, "large.txt", &[0u8; 2048]);

        let mut storage = FsQuotaAwareStorage::new(&target_dir, 10, 1024);
        let result = storage.store(&source_path).await;
        assert!(result.is_err());

        let stored_files = collect_files(&target_dir)?;
        assert!(stored_files.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_enforce_quota_by_count() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let source_dir = temp_dir.path().join("source");
        let target_dir = temp_dir.path().join("target");

        let mut storage = FsQuotaAwareStorage::new(&target_dir, 2, 1024 * 1024);

        // Create 3 files
        let source_files: [_; 3] = std::array::from_fn(|e| {
            let file_name = format!("file_{e}.txt");
            create_file_in(&source_dir, &file_name, b"data")
        });

        // Store 3 files
        storage.store(&source_files[0]).await?;
        storage.store(&source_files[1]).await?;
        storage.store(&source_files[2]).await?;

        // Check 2 files were copied
        let stored_files = collect_files(&target_dir)?;
        assert_eq!(stored_files.len(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_stores_evict_oldest() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let source_dir = temp_dir.path().join("source");
        let target_dir = temp_dir.path().join("target");

        let mut storage = FsQuotaAwareStorage::new(&target_dir, 2, 1024 * 1024);

        // Create 3 files
        let source_files: [_; 3] = std::array::from_fn(|e| {
            std::thread::sleep(Duration::from_millis(10));
            let file_name = format!("file_{e}.txt");
            let file_path = create_file_in(&source_dir, &file_name, b"data");
            (file_path, file_name)
        });

        // Store multiple files
        for source_file in source_files.iter() {
            storage.store(&source_file.0).await?;
        }

        // Check 2 last files are present
        let stored_files = collect_files(&target_dir)?;
        assert_eq!(stored_files.len(), 2);
        assert!(!stored_files.contains(&source_files[0].1));
        assert!(stored_files.contains(&source_files[1].1));
        assert!(stored_files.contains(&source_files[2].1));

        Ok(())
    }

    fn create_file_in(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content).unwrap();
        path
    }

    fn collect_files(path: impl AsRef<Path>) -> anyhow::Result<Vec<String>> {
        let Ok(list) = std::fs::read_dir(path) else {
            return Ok(vec![]);
        };
        Ok(list
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().into_string())
            .filter_map(|e| e.ok())
            .collect())
    }
}
