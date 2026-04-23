use crate::artifact_service::config::ArtifactConfig;
use crate::artifact_service::server::ArtifactServer;
use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::UNIX_EPOCH;
use tracing::warn;

#[derive(Debug, Deserialize)]
pub struct QueryArgs {
    mac: String,
}

#[derive(Debug, Serialize)]
struct FileInfo {
    name: String,
    ts: u64,
}

impl ArtifactServer {
    pub async fn get_artifact_list(Query(query): Query<QueryArgs>) -> Response {
        let config = ArtifactConfig::get();

        let mut file_groups = HashMap::<String, Vec<FileInfo>>::new();
        for folder_name in config.s2c_groups.iter() {
            let files = file_groups.entry(folder_name.to_string()).or_default();

            let tx_folder = config.tx_folder.join(folder_name);
            let Ok(tx_files) = tx_folder.read_dir() else {
                warn!("failed to read tx folder: {}", tx_folder.display());
                continue;
            };

            for entry in tx_files {
                let Ok(entry) = entry else {
                    continue;
                };

                let file_name = entry.file_name();
                let Some(file_name) = file_name.to_str() else {
                    warn!("invalid file name: {}", file_name.display());
                    continue;
                };

                if !file_name.starts_with(&query.mac) {
                    continue;
                }

                let Ok(metadata) = entry.metadata() else {
                    warn!("invalid metadata: {file_name}");
                    continue;
                };

                let modified = metadata.modified().ok();
                let modified = modified.and_then(|e| e.duration_since(UNIX_EPOCH).ok());

                files.push(FileInfo {
                    ts: modified.map_or(0, |e| e.as_secs()),
                    name: file_name.to_string(),
                });
            }
        }

        (StatusCode::OK, Json(file_groups)).into_response()
    }
}
