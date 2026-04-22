use crate::artifact_service::common::{
    ArtifactConfig, ArtifactFilter, ArtifactInfo, is_file_name_sanitized,
};
use crate::interface_manager::InterfaceInfo;
use crate::next_task_id;
use futures::StreamExt;
use std::net::Ipv6Addr;
use std::ops::Add;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument, trace, warn};

////////////////////////////////////////////////////////////////////////////////
pub struct ArtifactClient {
    if_info: InterfaceInfo,
    instance: Option<ArtifactClientInstance>,
}

impl ArtifactClient {
    pub fn new(if_info: InterfaceInfo) -> anyhow::Result<Self> {
        Ok(Self {
            if_info,
            instance: Default::default(),
        })
    }

    ////////////////////////////////////////////////////////////////////////////////
    #[instrument(skip_all, "artifact_client")]
    pub async fn start(&mut self, ip_address: Ipv6Addr) -> anyhow::Result<()> {
        debug!(%ip_address, "starting");

        if let Some(instance) = self.instance.take()
            && instance.ip_address == ip_address
        {
            self.instance = Some(instance);
            info!("already started");
            return Ok(());
        }

        info!(%ip_address, "started");
        self.instance = Some(ArtifactClientInstance::new(
            self.if_info.clone(),
            ip_address,
        )?);
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////
pub struct ArtifactClientInstance {
    ip_address: Ipv6Addr,
    _join_set: JoinSet<()>,
}

impl ArtifactClientInstance {
    fn new(if_info: InterfaceInfo, ip_address: Ipv6Addr) -> anyhow::Result<Self> {
        debug!("creating client");

        let client = reqwest::Client::builder()
            .interface(&if_info.if_name)
            .build()?;

        let actor = ArtifactClientInstanceActor {
            if_info,
            base_url: format!("http://[{}]:{}", ip_address, ArtifactConfig::PORT),
            client,
        };

        let mut join_set = JoinSet::new();
        join_set.spawn(actor.worker());

        Ok(Self {
            _join_set: join_set,
            ip_address,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////
struct ArtifactClientInstanceActor {
    if_info: InterfaceInfo,
    base_url: String,
    client: reqwest::Client,
}

impl ArtifactClientInstanceActor {
    const SYNC_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

    ////////////////////////////////////////////////////////////////////////////////
    #[instrument(skip_all, "artifact_client/worker", fields(task = next_task_id()))]
    async fn worker(self) {
        let config = ArtifactConfig::get();

        debug!("cleanup");
        if let Err(e) = tokio::fs::remove_dir_all(&config.rx_folder).await {
            error!(%e, "failed to remove rx folder: {}", config.rx_folder.display());
        }
        if let Err(e) = tokio::fs::remove_dir_all(&config.tx_folder).await {
            error!(%e, "failed to remove tx folder: {}", config.tx_folder.display());
        }

        loop {
            debug!("sync started");
            self.sync_files(&config).await;
            debug!("sync finished");
            tokio::time::sleep(Self::SYNC_INTERVAL).await;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn sync_files(&self, config: &ArtifactConfig) {
        debug!("fetching artifact list");
        let artifacts = match self.get_artifact_list().await {
            Ok(e) => e,
            Err(e) => return error!(%e, "failed to fetch artifact list"),
        };

        trace!("all available artifacts: {artifacts:#?}");
        for artifact in artifacts {
            debug!("downloading artifact: {artifact:#?}");

            if config.s2c_artifact_types.contains(&artifact.kind.as_str()) {
                warn!("skipping unsupported group {}", artifact.kind);
                continue;
            }

            if !is_file_name_sanitized(&artifact.kind) {
                warn!("invalid file group {}", artifact.kind);
                continue;
            }

            if !is_file_name_sanitized(&artifact.name) {
                warn!("invalid file name {}", artifact.name);
                continue;
            }

            let artifact_dir = config.archive_folder.join("rx").join(&artifact.kind);
            let artifact_path = artifact_dir.join(&artifact.name);

            if let Err(e) = tokio::fs::create_dir_all(&artifact_dir).await {
                error!(%e, "failed to create artifact dir: {}", artifact_dir.display());
                continue;
            }

            let archive_dir = config.archive_folder.join("rx").join(&artifact.kind);
            let archive_path = artifact_dir.join(&artifact.name);

            if let Err(e) = tokio::fs::create_dir_all(&archive_dir).await {
                error!(%e, "failed to create archive dir: {}", archive_dir.display());
                continue;
            }

            if let Ok(metadata) = artifact_path.metadata()
                && let Ok(modified) = metadata.modified()
                && let Ok(modified) = modified.duration_since(UNIX_EPOCH)
                && artifact.ts_secs == modified.as_secs()
            {
                info!("skipping up-to-date artifact: {}", artifact_path.display());
                continue;
            }

            if let Err(e) = self.get_artifact(&artifact, &artifact_path).await {
                error!(%e, "failed to fetch an artifact: {artifact:#?}");
                let _ = tokio::fs::remove_file(&artifact_path).await;
                continue;
            }

            if let Err(e) = tokio::fs::rename(&artifact_path, &archive_path).await {
                error!(src = ?artifact_path, dst = ?archive_path, %e, "failed to archive an artifact");
                let _ = tokio::fs::remove_file(&artifact_path).await;
                continue;
            }

            info!("artifact successfully downloaded: {archive_path:?}");
        }

        for artifact_type in config.c2s_artifact_types.iter() {
            let in_flight_dir = config.tx_folder.join(artifact_type);
            let archive_dir = config.archive_folder.join("tx").join(artifact_type);
            let failed_dir = config.failed_folder.join("tx").join(artifact_type);

            for dir in [&archive_dir, &failed_dir] {
                if let Err(e) = tokio::fs::create_dir_all(dir).await {
                    error!(?dir, %e, "failed to create a directory");
                    continue;
                }
            }

            let Ok(mut tx_files) = tokio::fs::read_dir(&in_flight_dir).await else {
                warn!("failed to read tx folder: {}", in_flight_dir.display());
                continue;
            };

            while let Ok(Some(entry)) = tx_files.next_entry().await {
                let path = entry.path();
                debug!("uploading artifact: {}", path.display());

                let file_name = entry.file_name();
                let Some(file_name) = file_name.to_str() else {
                    warn!("invalid file name: {}", file_name.display());
                    continue;
                };

                if let Err(e) = self.put_artifact(artifact_type, file_name, &path).await {
                    error!(%e, "failed to send artifact: {}", path.display());

                    let failed_path = failed_dir.join(file_name);
                    if let Err(e) = tokio::fs::rename(&path, &failed_path).await {
                        error!(?path, ?failed_path, %e, "failed to move file");
                        let _ = tokio::fs::remove_file(&path).await;
                    }
                } else {
                    info!("artifact sent successfully: {}", path.display());

                    let archive_path = archive_dir.join(file_name);
                    if let Err(e) = tokio::fs::rename(&path, &archive_path).await {
                        error!(?path, ?archive_path, %e, "failed to archive file");
                        let _ = tokio::fs::remove_file(&path).await;
                    }
                }
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn get_artifact_list(&self) -> anyhow::Result<Vec<ArtifactInfo>> {
        let url = format!("{}/artifacts", self.base_url);
        let filter = ArtifactFilter {
            mac: self.if_info.mac.to_string().replace(':', "-"),
        };

        let response = self.client.get(url).query(&filter).send().await?;
        let response = response.error_for_status()?;
        Ok(response.json::<Vec<ArtifactInfo>>().await?)
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn get_artifact(
        &self,
        artifact: &ArtifactInfo,
        target: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        let url = format!(
            "{}/artifacts/{}/{}",
            self.base_url, artifact.kind, artifact.name,
        );

        let response = self.client.get(url).send().await?;
        let response = response.error_for_status()?;
        let mut input = response.bytes_stream();

        let file = tokio::fs::File::create(target).await?;
        let mut output = tokio::io::BufWriter::new(file);

        while let Some(chunk) = input.next().await {
            output.write_all_buf(&mut chunk?).await?;
        }

        let ts = SystemTime::UNIX_EPOCH.add(Duration::from_secs(artifact.ts_secs));
        let file = output.into_inner().into_std().await;
        file.set_modified(ts)?;

        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////////
    async fn put_artifact(
        &self,
        artifact_type: &str,
        artifact_name: &str,
        source: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        let url = format!(
            "{}/artifacts/{artifact_type}/{artifact_name}",
            self.base_url,
        );

        let file = tokio::fs::File::open(source).await?;
        let stream = ReaderStream::new(file);

        self.client
            .post(url)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await?;

        Ok(())
    }
}
