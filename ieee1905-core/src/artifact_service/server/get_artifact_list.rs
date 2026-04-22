use crate::artifact_service::common::{ArtifactConfig, ArtifactFilter, ArtifactInfo};
use crate::artifact_service::server::ArtifactServerInstanceActor;
use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::time::UNIX_EPOCH;
use tracing::warn;

impl ArtifactServerInstanceActor {
    pub async fn get_artifact_list(Query(query): Query<ArtifactFilter>) -> Response {
        let config = ArtifactConfig::get();

        let mut file_groups = HashMap::<String, Vec<ArtifactInfo>>::new();
        for artifact_type in config.s2c_artifact_types.iter() {
            let files = file_groups.entry(artifact_type.to_string()).or_default();

            let tx_folder = config.tx_folder.join(artifact_type);
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

                files.push(ArtifactInfo {
                    kind: artifact_type.to_string(),
                    name: file_name.to_string(),
                    ts_secs: modified.map_or(0, |e| e.as_secs()),
                });
            }
        }

        (StatusCode::OK, Json(file_groups)).into_response()
    }
}
