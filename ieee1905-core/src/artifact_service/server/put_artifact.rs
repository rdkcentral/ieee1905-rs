use crate::artifact_service::common::{ArtifactConfig, is_file_name_sanitized};
use crate::artifact_service::server::ArtifactServerInstanceActor;
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
    artifact_type: String,
    artifact_name: String,
}

impl ArtifactServerInstanceActor {
    pub async fn put_artifact(path: axum::extract::Path<PathArgs>, body: Body) -> Response {
        let artifact_type = path.artifact_type.as_str();
        let artifact_name = path.artifact_name.as_str();

        let config = ArtifactConfig::get();
        if !config.c2s_artifact_types.contains(&artifact_type) {
            let message = format!("artifact type {artifact_type} is not supported");
            return (StatusCode::NOT_ACCEPTABLE, message).into_response();
        }

        if !is_file_name_sanitized(artifact_type) {
            let message = format!("invalid artifact type: {artifact_type}");
            return (StatusCode::NOT_ACCEPTABLE, message).into_response();
        }

        if !is_file_name_sanitized(artifact_name) {
            let message = format!("invalid artifact name: {artifact_name}");
            return (StatusCode::NOT_ACCEPTABLE, message).into_response();
        }

        async fn copy_to_file(mut input: BodyDataStream, output: &Path) -> anyhow::Result<()> {
            let mut file = tokio::fs::File::create(output).await?;
            while let Some(chunk) = input.next().await {
                file.write_all(&chunk?).await?;
            }
            Ok(())
        }

        let in_flight_dir = config.rx_folder.join(artifact_type);
        let in_flight_path = in_flight_dir.join(artifact_name);

        if let Err(e) = tokio::fs::create_dir_all(&in_flight_dir).await {
            error!(?in_flight_dir, %e, "failed to create a directory");
            let message = format!("failed to create a directory: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response();
        }

        let input_file_stream = body.into_data_stream();
        debug!(?in_flight_path, "saving file");

        match copy_to_file(input_file_stream, &in_flight_path).await {
            Ok(_) => {
                debug!(?in_flight_path, "archiving file");

                let mut storage = config.get_rx_archive_storage(artifact_type);
                if let Err(e) = storage.store(&in_flight_path).await {
                    error!(?in_flight_path, %e, "failed to archive file");
                    let _ = tokio::fs::remove_file(&in_flight_path).await;
                }

                StatusCode::NO_CONTENT.into_response()
            }
            Err(e) => {
                error!(?in_flight_path, %e, "failed to save file");

                let mut storage = config.get_rx_failure_storage(artifact_type);
                if let Err(e) = storage.store(&in_flight_path).await {
                    error!(?in_flight_path, %e, "failed to store file");
                    let _ = tokio::fs::remove_file(&in_flight_path).await;
                }

                let message = format!("failed to write file: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
    }
}
