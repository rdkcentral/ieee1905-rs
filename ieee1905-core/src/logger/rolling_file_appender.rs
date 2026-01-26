use chrono::{DateTime, Datelike, Local, Timelike};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

///////////////////////////////////////////////////////////////////////////
pub struct RollingFileAppender {
    folder: PathBuf,
    file_prefix: String,
    file_suffix: String,
    max_files: usize,
    max_file_size: usize,
    current_file: Option<CurrentFile>,
}

struct CurrentFile {
    date: DateTime<Local>,
    writer: BufWriter<File>,
    bytes_written: usize,
}

struct FileInfo {
    path: PathBuf,
    created_at: SystemTime,
}

impl RollingFileAppender {
    pub fn daily(folder: impl AsRef<Path>, file_prefix: &str, file_suffix: &str) -> Self {
        Self {
            folder: folder.as_ref().to_path_buf(),
            file_prefix: file_prefix.into(),
            file_suffix: file_suffix.into(),
            max_files: usize::MAX,
            max_file_size: usize::MAX,
            current_file: None,
        }
    }

    pub fn max_files(mut self, value: NonZeroUsize) -> Self {
        self.max_files = value.get();
        self
    }

    pub fn max_file_size(mut self, value: NonZeroUsize) -> Self {
        self.max_file_size = value.get();
        self
    }

    fn prune_old_logs(&self) -> Vec<FileInfo> {
        let files = std::fs::read_dir(&self.folder).map(|dir| {
            dir.filter_map(|entry| {
                let entry = entry.ok()?;

                let metadata = entry.metadata().ok()?;
                if !metadata.is_file() {
                    return None;
                }

                let filename = entry.file_name();
                let filename_str = filename.to_str()?;

                if !filename_str.starts_with(&self.file_prefix) {
                    return None;
                }
                if !filename_str.ends_with(&self.file_suffix) {
                    return None;
                }

                Some(FileInfo {
                    path: entry.path(),
                    created_at: metadata.created().ok()?,
                })
            })
            .collect::<Vec<_>>()
        });

        let mut files = match files {
            Ok(files) => files,
            Err(error) => {
                eprintln!("Error reading the log directory/files: {error}");
                return Vec::new();
            }
        };

        // (n-1) files remain, because we will create another log file
        if let Some(files_over) = files.len().checked_sub(self.max_files.saturating_sub(1)) {
            // sort the files by their creation timestamps.
            files.sort_by_key(|e| e.created_at);

            // delete files
            for info in files.iter().take(files_over) {
                let path = &info.path;
                if let Err(error) = std::fs::remove_file(path) {
                    eprintln!("Failed to remove old log file {}: {error}", path.display());
                }
            }
        }
        files
    }

    fn should_rollover(&self, file: &CurrentFile, now: &DateTime<Local>) -> bool {
        file.bytes_written > self.max_file_size
            || file.date.year() != now.year()
            || file.date.month() != now.month()
            || file.date.day() != now.day()
    }

    fn format_file_name(&self, now: &DateTime<Local>) -> String {
        format!(
            "{}{:04}{:02}{:02}_{:02}{:02}{:02}_{:03}{}",
            self.file_prefix,
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            now.timestamp_subsec_millis(),
            self.file_suffix
        )
    }

    fn get_current_writer(&mut self) -> std::io::Result<&mut CurrentFile> {
        let now = Local::now();
        if let Some(file) = self.current_file.take() {
            if !self.should_rollover(&file, &now) {
                return Ok(self.current_file.insert(file));
            }
        }

        std::fs::create_dir_all(&self.folder)?;
        self.prune_old_logs();

        let file_name = self.format_file_name(&now);
        let file_path = self.folder.join(file_name);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)?;

        Ok(self.current_file.insert(CurrentFile {
            date: now,
            writer: BufWriter::new(file),
            bytes_written: 0,
        }))
    }
}

impl Write for RollingFileAppender {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let file = self.get_current_writer()?;
        let size = file.writer.write(buf)?;
        file.bytes_written += size;
        Ok(size)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(file) = self.current_file.as_mut() {
            file.writer.flush()?;
        }
        Ok(())
    }
}
