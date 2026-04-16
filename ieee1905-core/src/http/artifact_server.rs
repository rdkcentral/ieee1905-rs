use crate::interface_manager::{
    call_rt_new_address_v6, call_rt_remove_address_v6, convert_mac_to_eui64, InterfaceInfo,
};
use crate::next_task_id;
use axum::body::{Body, BodyDataStream};
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures::StreamExt;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument};

pub struct ArtifactServer {
    if_info: InterfaceInfo,
    ip_address: Ipv6Addr,
    instance: Option<ArtifactServerInstance>,
}

impl ArtifactServer {
    pub const PORT: u16 = 6666;

    pub fn new(if_info: InterfaceInfo) -> Self {
        let ip_address = convert_mac_to_eui64(if_info.mac);

        Self {
            if_info,
            ip_address,
            instance: None,
        }
    }

    pub fn if_info(&self) -> &InterfaceInfo {
        &self.if_info
    }

    pub fn ip_address(&self) -> Ipv6Addr {
        self.ip_address
    }

    #[instrument(skip_all, "artifact_server")]
    pub async fn start(&mut self) -> anyhow::Result<()> {
        info!("starting server");

        if self.instance.is_some() {
            info!("server already started");
            return Ok(());
        }

        debug!(
            if_name = self.if_info.if_name,
            mac = %self.if_info.mac,
            ip_address = %self.ip_address,
            "assigning ip address to the interface",
        );
        call_rt_new_address_v6(self.if_info.if_index, self.ip_address).await?;

        debug!("starting tcp listener");
        let runtime = Handle::try_current()?;
        let address = SocketAddrV6::new(self.ip_address, Self::PORT, 0, self.if_info.if_index);
        let listener = TcpListener::bind(address).await?;

        debug!("starting server worker");
        let mut join_set = JoinSet::new();
        join_set.spawn(Self::worker(listener));

        info!("server successfully started");
        self.instance = Some(ArtifactServerInstance {
            runtime,
            if_info: self.if_info.clone(),
            ip_address: self.ip_address,
            _join_set: join_set,
        });
        Ok(())
    }

    pub fn stop(&mut self, if_name: &str) {
        self.instance.take_if(|e| e.if_info.if_name == if_name);
    }

    #[instrument(skip_all, "artifact_server/worker", fields(task = next_task_id()))]
    async fn worker(listener: TcpListener) {
        info!("worker started");
        let app = Router::new()
            .route("/", get(Self::get_root_page))
            .route("/firmware", get(Self::get_firmware))
            .route("/upload_file", post(Self::upload_file))
            .layer(DefaultBodyLimit::max(100 * 1024 * 1024));

        match axum::serve(listener, app).await {
            Ok(_) => info!("worker finished"),
            Err(e) => error!(%e, "worker failed"),
        }
    }

    #[instrument(skip_all, "artifact_server/get_root_page")]
    async fn get_root_page() -> String {
        info!("requested");
        let name = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");
        format!("{name} {version}")
    }

    #[instrument(skip_all, "artifact_server/get_firmware")]
    async fn get_firmware() -> Response {
        info!("requested");

        let file = match tokio::fs::File::open("firmware.bin").await {
            Ok(file) => file,
            Err(e) => {
                let message = format!("Failed to read firmware: {e}");
                return (StatusCode::NOT_FOUND, message).into_response();
            }
        };

        let stream = ReaderStream::new(file);
        let body = Body::from_stream(stream);
        let headers = [(axum::http::header::CONTENT_TYPE, "application/octet-stream")];

        (StatusCode::OK, headers, body).into_response()
    }

    #[instrument(skip_all, "artifact_server/upload_file")]
    async fn upload_file(request: Request) -> Response {
        async fn inner(mut stream: BodyDataStream) -> anyhow::Result<()> {
            let mut file = tokio::fs::File::create("firmware_uploaded.bin").await?;

            while let Some(chunk) = stream.next().await {
                file.write_all(&chunk?).await?;
            }
            Ok(())
        }

        let stream = request.into_body().into_data_stream();
        match inner(stream).await {
            Ok(_) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => {
                let message = format!("Failed to write file: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
            }
        }
    }
}

pub struct ArtifactServerInstance {
    runtime: Handle,
    if_info: InterfaceInfo,
    ip_address: Ipv6Addr,
    _join_set: JoinSet<()>,
}

impl Drop for ArtifactServerInstance {
    fn drop(&mut self) {
        self.runtime.spawn(call_rt_remove_address_v6(
            self.if_info.if_index,
            self.ip_address,
        ));
    }
}
