use crate::artifact_service::common::{ArtifactConfig, is_file_name_sanitized};
use crate::artifact_service::server::ArtifactServerInstanceActor;
use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde::Deserialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio_util::io::ReaderStream;
use tracing::error;

#[derive(Debug, Deserialize)]
pub struct PathArgs {
    artifact_type: String,
    artifact_name: String,
}

impl ArtifactServerInstanceActor {
    pub async fn get_artifact(path: axum::extract::Path<PathArgs>) -> Response {
        let artifact_type = path.artifact_type.as_str();
        let artifact_name = path.artifact_name.as_str();

        let config = ArtifactConfig::get();
        if !config.s2c_artifact_types.contains(&artifact_type) {
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

        let file_path = config.tx_folder.join(artifact_type).join(artifact_name);
        let file = match tokio::fs::File::open(&file_path).await {
            Ok(file) => file,
            Err(e) => {
                error!(?file_path, %e, "failed to read file");
                let message = format!("failed to read file: {e}");
                return (StatusCode::NOT_FOUND, message).into_response();
            }
        };

        // stream the file to the client, then move it into the archive so the same
        // artifact is not served (and re-downloaded) on the next sync.
        // the move is only performed once the file has been fully read without error.
        let stream_sent = Arc::new(AtomicBool::new(true));
        let stream = ReaderStream::new(file).inspect({
            let stream_sent = stream_sent.clone();
            move |chunk| {
                if chunk.is_err() {
                    stream_sent.store(false, Ordering::Relaxed);
                }
            }
        });

        let artifact_type = artifact_type.to_string();
        let archive = futures::stream::once(async move {
            if stream_sent.load(Ordering::Relaxed) {
                let mut storage = ArtifactConfig::get().get_tx_archive_storage(&artifact_type);
                if let Err(e) = storage.store(&file_path).await {
                    error!(?file_path, %e, "failed to archive served artifact");
                    let _ = tokio::fs::remove_file(&file_path).await;
                }
            }
            Ok(Bytes::new())
        });

        let body = Body::from_stream(stream.chain(archive));
        let headers = [(CONTENT_TYPE, "application/octet-stream")];

        (StatusCode::OK, headers, body).into_response()
    }
}
