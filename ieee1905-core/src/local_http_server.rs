use crate::interface_manager::{
    call_rt_new_address_v6, call_rt_remove_address_v6, convert_mac_to_eui64, get_interface_info,
    InterfaceInfo,
};
use crate::next_task_id;
use anyhow::bail;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::net::{Ipv6Addr, SocketAddrV6};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument};

#[derive(Default)]
pub struct LocalHttpServer {
    instance: Option<LocalHttpServerInstance>,
}

pub struct LocalHttpServerInstance {
    runtime: Handle,
    interface: InterfaceInfo,
    ip_address: Ipv6Addr,
    _join_set: JoinSet<()>,
}

impl LocalHttpServer {
    const PORT: u16 = 6666;

    #[instrument(skip_all, "http_server")]
    pub async fn start(&mut self, if_name: &str) -> anyhow::Result<&mut LocalHttpServerInstance> {
        info!(if_name, "starting server");

        let Some(interface) = get_interface_info(if_name) else {
            bail!("interface {if_name} not found");
        };

        if let Some(instance) = self.instance.take() {
            if instance.interface.mac == interface.mac {
                info!("server already started");
                return Ok(self.instance.insert(instance));
            }
        }

        let runtime = Handle::try_current()?;
        let ip_address = convert_mac_to_eui64(interface.mac);

        debug!(if_name, mac = %interface.mac, %ip_address, "assigning ip address to the interface");
        call_rt_new_address_v6(interface.if_index, ip_address).await?;

        debug!("starting tcp listener");
        let socket_address = SocketAddrV6::new(ip_address, Self::PORT, 0, interface.if_index);
        let listener = TcpListener::bind(socket_address).await?;

        debug!("starting server worker");
        let mut join_set = JoinSet::new();
        join_set.spawn(Self::worker(listener));

        info!("server successfully started");
        Ok(self.instance.insert(LocalHttpServerInstance {
            runtime,
            interface,
            ip_address,
            _join_set: join_set,
        }))
    }

    pub fn stop(&mut self, if_name: &str) {
        self.instance.take_if(|e| e.interface.if_name == if_name);
    }

    #[instrument(skip_all, "http_server_worker", fields(task = next_task_id()))]
    async fn worker(listener: TcpListener) {
        info!("worker started");
        let app = Router::new()
            .route("/", get(Self::get_root_page))
            .route("/firmware", get(Self::get_firmware));

        match axum::serve(listener, app).await {
            Ok(_) => info!("worker finished"),
            Err(e) => error!(%e, "worker failed"),
        }
    }

    #[instrument(skip_all, "http_server/get_root_page")]
    async fn get_root_page() -> String {
        info!("requested");
        let name = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");
        format!("{name} {version}")
    }

    #[instrument(skip_all, "http_server/get_firmware")]
    async fn get_firmware() -> Response {
        info!("requested");

        let file = match tokio::fs::File::open("firmware.txt").await {
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
}

impl Drop for LocalHttpServerInstance {
    fn drop(&mut self) {
        self.runtime.spawn(call_rt_remove_address_v6(
            self.interface.if_index,
            self.ip_address,
        ));
    }
}
