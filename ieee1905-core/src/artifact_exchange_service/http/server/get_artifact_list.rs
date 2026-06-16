use crate::artifact_exchange_service::http::common::{
    ArtifactExchangeConfig, ArtifactExchangeFilter, parse_mac_as_file_prefix,
};
use crate::artifact_exchange_service::http::server::ArtifactExchangeServerInstanceActor;
use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use tracing::warn;

impl ArtifactExchangeServerInstanceActor {
    pub async fn get_artifact_list(Query(mut query): Query<ArtifactExchangeFilter>) -> Response {
        let config = ArtifactExchangeConfig::get();
        query.mac.make_ascii_lowercase();

        if parse_mac_as_file_prefix(&query.mac).is_none() {
            return (StatusCode::BAD_REQUEST, "invalid `mac` argument").into_response();
        }

        let mut file_groups = HashMap::<String, Vec<String>>::new();
        for artifact_type in config.s2c_artifact_types.iter() {
            let files = file_groups.entry(artifact_type.to_string()).or_default();

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

                files.push(file_name.to_string());
            }
        }

        (StatusCode::OK, Json(file_groups)).into_response()
    }
}
