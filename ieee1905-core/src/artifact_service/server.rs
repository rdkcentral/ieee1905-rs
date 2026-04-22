mod get_artifact;
mod get_artifact_list;
mod put_artifact;

use crate::artifact_service::common::ArtifactConfig;
use crate::interface_manager::{
    InterfaceInfo, call_rt_new_address_v6, call_rt_remove_address_v6, convert_mac_to_eui64,
};
use crate::{TopologyDatabase, next_task_id};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, put};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, instrument};

////////////////////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////////////////////
    pub fn if_info(&self) -> &InterfaceInfo {
        &self.if_info
    }

    ////////////////////////////////////////////////////////////////////////////////
    pub fn ip_address(&self) -> Ipv6Addr {
        self.ip_address
    }

    ////////////////////////////////////////////////////////////////////////////////
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

        self.instance = Some({
            let topo_db = self.topo_db.clone();
            let if_info = self.if_info.clone();
            ArtifactServerInstance::new(topo_db, if_info, self.ip_address).await?
        });
        info!("server started");
        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////////
    pub fn stop(&mut self, if_name: &str) {
        info!("server stopped");
        self.instance.take_if(|e| e.if_info.if_name == if_name);
    }
}

////////////////////////////////////////////////////////////////////////////////
pub struct ArtifactServerInstance {
    topo_db: Arc<TopologyDatabase>,
    runtime: Handle,
    if_info: InterfaceInfo,
    ip_address: Ipv6Addr,
    _join_set: JoinSet<()>,
}

impl ArtifactServerInstance {
    async fn new(
        topo_db: Arc<TopologyDatabase>,
        if_info: InterfaceInfo,
        ip_address: Ipv6Addr,
    ) -> anyhow::Result<Self> {
        debug!("starting tcp listener");
        let runtime = Handle::try_current()?;
        let port = ArtifactConfig::PORT;
        let so_address = SocketAddrV6::new(ip_address, port, 0, if_info.if_index);
        let listener = TcpListener::bind(so_address).await?;

        debug!("starting server worker");
        let mut join_set = JoinSet::new();
        join_set.spawn(ArtifactServerInstanceActor.worker(listener));

        info!(
            if_name = if_info.if_name,
            ip_address = %ip_address,
            "server successfully started",
        );
        topo_db.set_artifact_server_address(Some(ip_address));

        Ok(ArtifactServerInstance {
            topo_db,
            runtime,
            if_info,
            ip_address,
            _join_set: join_set,
        })
    }
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

////////////////////////////////////////////////////////////////////////////////
struct ArtifactServerInstanceActor;

impl ArtifactServerInstanceActor {
    ////////////////////////////////////////////////////////////////////////////////
    #[instrument(skip_all, "artifact_server/worker", fields(task = next_task_id()))]
    async fn worker(self, listener: TcpListener) {
        let config = ArtifactConfig::get();

        debug!("cleanup");
        if let Err(e) = tokio::fs::remove_dir_all(&config.rx_folder).await {
            error!(%e, "failed to remove rx folder: {}", config.rx_folder.display());
        }

        info!("worker started");
        let app = Router::new()
            .route("/", get(Self::get_root_page))
            .route(
                "/artifacts/{artifact_type}/{artifact_name}",
                get(Self::get_artifact),
            )
            .route(
                "/artifacts/{artifact_type}/{artifact_name}",
                put(Self::put_artifact),
            )
            .route("/artifacts", get(Self::get_artifact_list))
            .layer(TraceLayer::new_for_http())
            .layer(DefaultBodyLimit::max(100 * 1024 * 1024));

        match axum::serve(listener, app).await {
            Ok(_) => info!("worker finished"),
            Err(e) => error!(%e, "worker failed"),
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn get_root_page() -> String {
        let name = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");
        format!("{name} {version}")
    }
}
