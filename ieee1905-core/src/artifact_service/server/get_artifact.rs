use crate::artifact_service::config::ArtifactConfig;
use crate::artifact_service::server::{ArtifactServer, is_file_name_sanitized};
use axum::body::Body;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tokio_util::io::ReaderStream;
use tracing::error;

#[derive(Debug, Deserialize)]
pub struct PathArgs {
    group: String,
    file: String,
}

impl ArtifactServer {
    pub async fn get_artifact(path: axum::extract::Path<PathArgs>) -> Response {
        let config = ArtifactConfig::get();
        if !config.s2c_groups.contains(&path.group.as_str()) {
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

        let file_path = config.tx_folder.join(&path.group).join(&path.file);
        let file = match tokio::fs::File::open(&file_path).await {
            Ok(file) => file,
            Err(e) => {
                error!(?file_path, %e, "failed to read file");
                let message = format!("failed to read file: {e}");
                return (StatusCode::NOT_FOUND, message).into_response();
            }
        };

        let stream = ReaderStream::new(file);
        let body = Body::from_stream(stream);
        let headers = [(CONTENT_TYPE, "application/octet-stream")];

        (StatusCode::OK, headers, body).into_response()
    }
}
