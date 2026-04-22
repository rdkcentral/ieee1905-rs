use crate::artifact_service::config::ArtifactConfig;
use crate::artifact_service::server::{ArtifactServer, is_file_name_sanitized};
use axum::body::{Body, BodyDataStream};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde::Deserialize;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error};

#[derive(Debug, Deserialize)]
pub struct PathArgs {
    group: String,
    file: String,
}

impl ArtifactServer {
    pub async fn put_artifact(path: axum::extract::Path<PathArgs>, body: Body) -> Response {
        let config = ArtifactConfig::get();
        if !config.c2s_groups.contains(&path.group.as_str()) {
            let message = format!("file group {} is not supported", path.group);
            return (StatusCode::NOT_ACCEPTABLE, message).into_response();
        }

        if !is_file_name_sanitized(&path.group) {
            let message = format!("invalid file group: {}", path.group);
            return (StatusCode::NOT_ACCEPTABLE, message).into_response();
        }

        if !is_file_name_sanitized(&path.file) {
            let message = format!("invalid file name: {}", path.file);
            return (StatusCode::NOT_ACCEPTABLE, message).into_response();
        }

        async fn copy_to_file(mut input: BodyDataStream, output: &Path) -> anyhow::Result<()> {
            let mut file = tokio::fs::File::create(output).await?;
            while let Some(chunk) = input.next().await {
                file.write_all(&chunk?).await?;
            }
            Ok(())
        }

        let in_flight_dir = config.rx_folder.join(&path.group);
        let in_flight_path = in_flight_dir.join(&path.file);

        let archive_dir = config.archive_folder.join(&path.group);
        let archive_path = archive_dir.join(&path.file);

        let failed_dir = config.failed_folder.join(&path.group);
        let failed_path = failed_dir.join(&path.file);

        for dir in [&in_flight_dir, &archive_dir, &failed_dir] {
            if let Err(e) = tokio::fs::create_dir_all(dir).await {
                error!(?dir, %e, "failed to create a directory");
                let message = format!("failed to create a directory: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
            }
        }

        let input_file_stream = body.into_data_stream();
        debug!(?in_flight_path, "saving file");
        if let Err(e) = copy_to_file(input_file_stream, &in_flight_path).await {
            if let Err(e) = tokio::fs::rename(&in_flight_path, &failed_path).await {
                error!(?in_flight_path, ?failed_path, %e, "failed to move file");
            }
            error!(?in_flight_path, %e, "failed to save file");
            let message = format!("failed to write file: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
        }

        debug!(?in_flight_path, "archiving file");
        if let Err(e) = tokio::fs::rename(&in_flight_path, &archive_path).await {
            error!(?in_flight_path, ?archive_path, %e, "failed to archive file");
        }

        StatusCode::NO_CONTENT.into_response()
    }
}
