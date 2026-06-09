use crate::artifact_exchange_service::common::{
    ArtifactExchangeConfig, ArtifactExchangeFilter, format_mac_as_file_prefix,
    is_file_name_sanitized,
};
use crate::interface_manager::{
    InterfaceInfo, call_rt_new_address_v6, call_rt_remove_address_v6, convert_mac_to_eui64,
};
use crate::next_task_id;
use futures::StreamExt;
use pnet::util::MacAddr;
use reqwest::Url;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::ErrorKind;
use std::net::Ipv6Addr;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::runtime::Handle;
use tokio::task::JoinSet;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument, trace, warn};

////////////////////////////////////////////////////////////////////////////////
#[derive(Debug)]
pub struct ArtifactExchangeClientFactory {
    runtime: Handle,
    if_info: InterfaceInfo,
    local_ip_address: Ipv6Addr,
}

impl ArtifactExchangeClientFactory {
    ////////////////////////////////////////////////////////////////////////////////
    pub async fn new(if_info: InterfaceInfo) -> anyhow::Result<Self> {
        let config = ArtifactExchangeConfig::get();
        let runtime = Handle::try_current()?;
        let local_ip_address = convert_mac_to_eui64(if_info.mac);

        debug!(
            if_name = if_info.if_name,
            mac = %if_info.mac,
            ip_address = %local_ip_address,
            "assigning ip address to the interface",
        );
        call_rt_new_address_v6(if_info.if_index, local_ip_address).await?;

        if let Err(e) = tokio::fs::remove_dir_all(&config.rx_folder).await
            && e.kind() != ErrorKind::NotFound
        {
            error!(%e, "failed to remove rx folder: {}", config.rx_folder.display());
        }

        Ok(Self {
            runtime,
            if_info,
            local_ip_address,
        })
    }

    ////////////////////////////////////////////////////////////////////////////////
    pub fn start(
        &self,
        remote_mac_address: MacAddr,
        base_url: &str,
    ) -> anyhow::Result<ArtifactExchangeClient> {
        ArtifactExchangeClient::new(self.if_info.clone(), remote_mac_address, base_url)
    }
}

impl Drop for ArtifactExchangeClientFactory {
    ////////////////////////////////////////////////////////////////////////////////
    fn drop(&mut self) {
        debug!(
            if_name = self.if_info.if_name,
            mac = %self.if_info.mac,
            ip_address = %self.local_ip_address,
            "clearing ip address to the interface",
        );
        self.runtime.spawn(call_rt_remove_address_v6(
            self.if_info.if_index,
            self.local_ip_address,
        ));
    }
}

////////////////////////////////////////////////////////////////////////////////
pub struct ArtifactExchangeClient {
    base_url: String,
    _join_set: JoinSet<()>,
}

impl ArtifactExchangeClient {
    ////////////////////////////////////////////////////////////////////////////////
    fn new(
        if_info: InterfaceInfo,
        remote_mac_address: MacAddr,
        base_url: &str,
    ) -> anyhow::Result<Self> {
        let mut base_url_str = Cow::Borrowed(base_url);
        if !base_url_str.ends_with('/') {
            base_url_str.to_mut().push('/');
        }

        let base_url = Url::parse(&base_url_str)?;
        debug!(mac = %remote_mac_address, %base_url, "creating client");

        let client = reqwest::Client::builder()
            .interface(&if_info.if_name)
            .build()?;

        info!(mac = %remote_mac_address, %base_url, "client created");

        let actor = ArtifactExchangeClientActor {
            if_info,
            remote_mac_address,
            base_url,
            client,
        };

        let mut join_set = JoinSet::new();
        join_set.spawn(actor.worker());

        Ok(Self {
            base_url: base_url_str.into_owned(),
            _join_set: join_set,
        })
    }
}

impl Debug for ArtifactExchangeClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ArtifactExchangeClient({})", self.base_url)
    }
}

////////////////////////////////////////////////////////////////////////////////
struct ArtifactExchangeClientActor {
    if_info: InterfaceInfo,
    remote_mac_address: MacAddr,
    base_url: Url,
    client: reqwest::Client,
}

impl ArtifactExchangeClientActor {
    const UPLOAD_SYNC_INTERVAL: Duration = Duration::from_mins(1);
    const DOWNLOAD_SYNC_INTERVAL: Duration = Duration::from_mins(10);

    ////////////////////////////////////////////////////////////////////////////////
    async fn worker(self) {
        let config = ArtifactExchangeConfig::get();

        futures::join!(
            self.upload_artifacts_worker(config),
            self.download_artifacts_worker(config),
        );
    }

    ////////////////////////////////////////////////////////////////////////////////
    #[instrument(skip_all, name = "artifact_exchange_client/upload", fields(task = next_task_id()))]
    async fn upload_artifacts_worker(&self, config: &ArtifactExchangeConfig) {
        loop {
            let instant = Instant::now();
            info!(remote = %self.remote_mac_address, "upload sync started");

            for artifact_type in config.c2s_artifact_types.iter() {
                self.upload_artifacts_by_type(config, artifact_type).await;
            }

            info!("upload sync finished in {:?}", instant.elapsed());
            tokio::time::sleep(Self::UPLOAD_SYNC_INTERVAL).await;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn upload_artifacts_by_type(&self, config: &ArtifactExchangeConfig, artifact_type: &str) {
        let in_flight_dir = config.tx_folder.join(artifact_type);
        let filter_mac = format_mac_as_file_prefix(self.remote_mac_address);

        let Ok(mut tx_files) = tokio::fs::read_dir(&in_flight_dir).await else {
            return debug!("tx folder is not available: {in_flight_dir:?}");
        };

        while let Ok(Some(entry)) = tx_files.next_entry().await {
            let path = entry.path();
            debug!("uploading artifact: {path:?}");

            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                warn!("invalid file name: {file_name:?}");
                continue;
            };

            if !file_name.starts_with(&filter_mac) {
                debug!("skipping file, different target mac: {file_name:?}");
                continue;
            }

            if let Err(e) = self.put_artifact(artifact_type, file_name, &path).await {
                error!(%e, "failed to send artifact: {path:?}");

                let mut storage = config.get_tx_failure_storage(artifact_type);
                if let Err(e) = storage.store(&path).await {
                    error!(%e, "failed to move file {path:?}");
                    let _ = tokio::fs::remove_file(&path).await;
                }
            } else {
                info!("artifact sent successfully: {}", path.display());

                let mut storage = config.get_tx_archive_storage(artifact_type);
                if let Err(e) = storage.store(&path).await {
                    error!(%e, "failed to archive file {path:?}");
                    let _ = tokio::fs::remove_file(&path).await;
                }
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    #[instrument(skip_all, name = "artifact_exchange_client/download", fields(task = next_task_id()))]
    async fn download_artifacts_worker(&self, config: &ArtifactExchangeConfig) {
        loop {
            let instant = Instant::now();
            info!(remote = %self.remote_mac_address, "download sync started");

            self.download_artifacts(config).await;
            info!("download sync finished in {:?}", instant.elapsed());

            tokio::time::sleep(Self::DOWNLOAD_SYNC_INTERVAL).await;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn download_artifacts(&self, config: &ArtifactExchangeConfig) {
        debug!("fetching artifact list");
        let artifacts = match self.get_artifact_list().await {
            Ok(e) => e,
            Err(e) => return error!(%e, "failed to fetch artifact list"),
        };

        let artifacts = artifacts
            .iter()
            .flat_map(|(k, v)| v.iter().map(move |e| (k, e)))
            .collect::<Vec<_>>();

        trace!("all available artifacts: {artifacts:#?}");
        for (kind, name) in artifacts {
            debug!("downloading artifact: {kind}/{name}");

            if !config.s2c_artifact_types.contains(&kind.as_str()) {
                warn!("skipping unsupported group {kind}");
                continue;
            }

            if !is_file_name_sanitized(kind) {
                warn!("invalid file group {kind}");
                continue;
            }

            if !is_file_name_sanitized(name) {
                warn!("invalid file name {name}");
                continue;
            }

            let artifact_dir = config.rx_folder.join(kind);
            let artifact_path = artifact_dir.join(name);

            if let Err(e) = tokio::fs::create_dir_all(&artifact_dir).await {
                error!(%e, "failed to create artifact dir: {artifact_dir:?}");
                continue;
            }

            if let Err(e) = self.get_artifact(kind, name, &artifact_path).await {
                error!(%e, "failed to fetch an artifact: {kind}/{name}");
                let _ = tokio::fs::remove_file(&artifact_path).await;
                continue;
            }

            let mut storage = config.get_rx_archive_storage(kind);
            if let Err(e) = storage.store(&artifact_path).await {
                error!(%e, "failed to archive an artifact {artifact_path:?}");
                let _ = tokio::fs::remove_file(&artifact_path).await;
                continue;
            }

            info!("artifact successfully downloaded: {artifact_path:?}");
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn get_artifact_list(&self) -> anyhow::Result<HashMap<String, Vec<String>>> {
        let url = self.base_url.join("artifacts")?;
        let filter = ArtifactExchangeFilter {
            mac: format_mac_as_file_prefix(self.if_info.mac),
        };

        let response = self.client.get(url).query(&filter).send().await?;
        let response = response.error_for_status()?;
        Ok(response.json().await?)
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn get_artifact(
        &self,
        artifact_kind: &str,
        artifact_name: &str,
        target: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        let relative_url = format!("artifacts/{artifact_kind}/{artifact_name}");
        let url = self.base_url.join(&relative_url)?;

        let response = self.client.get(url).send().await?;
        let response = response.error_for_status()?;
        let mut input = response.bytes_stream();

        let file = tokio::fs::File::create(target).await?;
        let mut output = tokio::io::BufWriter::new(file);

        while let Some(chunk) = input.next().await {
            output.write_all_buf(&mut chunk?).await?;
        }
        output.flush().await?;

        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn put_artifact(
        &self,
        artifact_type: &str,
        artifact_name: &str,
        source: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        let relative_url = format!("artifacts/{artifact_type}/{artifact_name}");
        let url = self.base_url.join(&relative_url)?;

        let file = tokio::fs::File::open(source).await?;
        let stream = ReaderStream::new(file);

        self.client
            .put(url)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}
