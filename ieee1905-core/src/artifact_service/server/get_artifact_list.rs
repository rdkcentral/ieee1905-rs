use crate::artifact_service::common::{ArtifactConfig, ArtifactFilter, ArtifactInfo};
use crate::artifact_service::server::ArtifactServerInstanceActor;
use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::time::UNIX_EPOCH;
use tracing::warn;

impl ArtifactServerInstanceActor {
    pub async fn get_artifact_list(Query(mut query): Query<ArtifactFilter>) -> Response {
        let config = ArtifactConfig::get();
        query.mac.make_ascii_lowercase();

        let mut files = Vec::new();
        for artifact_type in config.s2c_artifact_types.iter() {
            let tx_folder = config.tx_folder.join(artifact_type);
            let Ok(mut tx_files) = tokio::fs::read_dir(&tx_folder).await else {
                warn!("failed to read tx folder: {}", tx_folder.display());
                continue;
            };

            while let Ok(Some(entry)) = tx_files.next_entry().await {
                let file_name = entry.file_name();
                let Some(file_name) = file_name.to_str() else {
                    warn!("invalid file name: {}", file_name.display());
                    continue;
                };

                if !file_name.starts_with(&query.mac) {
                    continue;
                }

                let Ok(metadata) = entry.metadata().await else {
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

        (StatusCode::OK, Json(files)).into_response()
    }
}
