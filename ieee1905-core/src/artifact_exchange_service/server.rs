mod get_artifact;
mod get_artifact_list;
mod put_artifact;

use crate::artifact_exchange_service::common::ArtifactExchangeConfig;
use crate::interface_manager::{
    InterfaceInfo, call_rt_new_address_v6, call_rt_remove_address_v6, convert_mac_to_eui64,
};
use crate::{TopologyDatabase, next_task_id, spawn_join_set_named, spawn_on_named};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, put};
use std::io::ErrorKind;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, instrument};

////////////////////////////////////////////////////////////////////////////////
pub struct ArtifactExchangeServer {
    topo_db: Arc<TopologyDatabase>,
    if_info: InterfaceInfo,
    ip_address: Ipv6Addr,
    instance: Option<ArtifactExchangeServerInstance>,
}

impl ArtifactExchangeServer {
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
    pub fn format_base_url(ipv6: Ipv6Addr) -> String {
        format!("http://[{ipv6}]:{}/", ArtifactExchangeConfig::PORT)
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
    #[instrument(skip_all, name = "artifact_exchange_server")]
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
            ArtifactExchangeServerInstance::new(topo_db, if_info, self.ip_address).await?
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
pub struct ArtifactExchangeServerInstance {
    topo_db: Arc<TopologyDatabase>,
    runtime: Handle,
    if_info: InterfaceInfo,
    ip_address: Ipv6Addr,
    _join_set: JoinSet<()>,
}

impl ArtifactExchangeServerInstance {
    async fn new(
        topo_db: Arc<TopologyDatabase>,
        if_info: InterfaceInfo,
        ip_address: Ipv6Addr,
    ) -> anyhow::Result<Self> {
        debug!("starting tcp listener");
        let runtime = Handle::try_current()?;
        let port = ArtifactExchangeConfig::PORT;
        let so_address = SocketAddrV6::new(ip_address, port, 0, if_info.if_index);
        let listener = TcpListener::bind(so_address).await?;

        debug!("starting server worker");
        let mut join_set = JoinSet::new();
        spawn_join_set_named(
            "artifact_exchange_server/worker",
            None,
            &mut join_set,
            ArtifactExchangeServerInstanceActor.worker(listener),
        );

        info!(
            if_name = if_info.if_name,
            ip_address = %ip_address,
            "server successfully started",
        );
        topo_db.set_artifact_exchange_server_ip_address(Some(ip_address));

        Ok(ArtifactExchangeServerInstance {
            topo_db,
            runtime,
            if_info,
            ip_address,
            _join_set: join_set,
        })
    }
}

impl Drop for ArtifactExchangeServerInstance {
    fn drop(&mut self) {
        debug!(
            if_name = self.if_info.if_name,
            mac = %self.if_info.mac,
            ip_address = %self.ip_address,
            "clearing ip address to the interface",
        );
        self.topo_db.set_artifact_exchange_server_ip_address(None);
        spawn_on_named(
            "artifact_exchange_server/drop",
            &self.runtime,
            call_rt_remove_address_v6(self.if_info.if_index, self.ip_address),
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
pub(crate) struct ArtifactExchangeServerInstanceActor;

impl ArtifactExchangeServerInstanceActor {
    ////////////////////////////////////////////////////////////////////////////////
    #[instrument(skip_all, name = "artifact_exchange_server/worker", fields(task = next_task_id()))]
    async fn worker(self, listener: TcpListener) {
        let config = ArtifactExchangeConfig::get();

        debug!("cleanup");
        if let Err(e) = tokio::fs::remove_dir_all(&config.rx_folder).await
            && e.kind() != ErrorKind::NotFound
        {
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
