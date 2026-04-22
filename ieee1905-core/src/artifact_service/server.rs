mod get_artifact;
mod get_artifact_list;
mod put_artifact;

use crate::artifact_service::config::ArtifactConfig;
use crate::interface_manager::{
    InterfaceInfo, call_rt_new_address_v6, call_rt_remove_address_v6, convert_mac_to_eui64,
};
use crate::{TopologyDatabase, next_task_id};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, put};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::path::{Component, Path};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, instrument};

pub struct ArtifactServer {
    topo_db: Arc<TopologyDatabase>,
    if_info: InterfaceInfo,
    ip_address: Ipv6Addr,
    instance: Option<ArtifactServerInstance>,
}

impl ArtifactServer {
    pub fn new(topo_db: Arc<TopologyDatabase>, if_info: InterfaceInfo) -> Self {
        let ip_address = convert_mac_to_eui64(if_info.mac);

        Self {
            topo_db,
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
        debug!("starting server");

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
        let port = ArtifactConfig::PORT;
        let ip_address = self.ip_address;
        let so_address = SocketAddrV6::new(ip_address, port, 0, self.if_info.if_index);
        let listener = TcpListener::bind(so_address).await?;

        debug!("starting server worker");
        let mut join_set = JoinSet::new();
        join_set.spawn(Self::worker(listener));

        info!(
            if_name = self.if_info.if_name,
            ip_address = %self.ip_address,
            "server successfully started",
        );
        self.topo_db.set_artifact_server_address(Some(ip_address));
        self.instance = Some(ArtifactServerInstance {
            topo_db: self.topo_db.clone(),
            runtime,
            if_info: self.if_info.clone(),
            ip_address: self.ip_address,
            _join_set: join_set,
        });
        Ok(())
    }

    pub fn stop(&mut self, if_name: &str) {
        info!("server stopped");
        self.instance.take_if(|e| e.if_info.if_name == if_name);
    }

    #[instrument(skip_all, "artifact_server/worker", fields(task = next_task_id()))]
    async fn worker(listener: TcpListener) {
        info!("worker started");
        let app = Router::new()
            .route("/", get(Self::get_root_page))
            .route("/artifacts/{group}/{file}", get(Self::get_artifact))
            .route("/artifacts/{group}/{file}", put(Self::put_artifact))
            .route("/artifacts", get(Self::get_artifact_list))
            .layer(TraceLayer::new_for_http())
            .layer(DefaultBodyLimit::max(100 * 1024 * 1024));

        match axum::serve(listener, app).await {
            Ok(_) => info!("worker finished"),
            Err(e) => error!(%e, "worker failed"),
        }
    }

    async fn get_root_page() -> String {
        let name = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");
        format!("{name} {version}")
    }
}

pub struct ArtifactServerInstance {
    topo_db: Arc<TopologyDatabase>,
    runtime: Handle,
    if_info: InterfaceInfo,
    ip_address: Ipv6Addr,
    _join_set: JoinSet<()>,
}

impl Drop for ArtifactServerInstance {
    fn drop(&mut self) {
        self.topo_db.set_artifact_server_address(None);
        self.runtime.spawn(call_rt_remove_address_v6(
            self.if_info.if_index,
            self.ip_address,
        ));
    }
}

fn is_file_name_sanitized(name: impl AsRef<Path>) -> bool {
    let mut components = name.as_ref().components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None),
    )
}
