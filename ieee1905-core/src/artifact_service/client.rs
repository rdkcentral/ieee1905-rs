use crate::artifact_service::server::ArtifactServer;
use crate::interface_manager::InterfaceInfo;
use futures::StreamExt;
use std::net::Ipv6Addr;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use tracing::{debug, info, instrument};

pub struct ArtifactClient {
    if_info: InterfaceInfo,
    instance: Option<ArtifactClientInstance>,
}

impl ArtifactClient {
    pub const PORT: u16 = ArtifactServer::PORT;

    pub fn new(if_info: InterfaceInfo) -> anyhow::Result<Self> {
        Ok(Self {
            if_info,
            instance: Default::default(),
        })
    }

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
        self.instance = Some(ArtifactClientInstance::new(&self.if_info, ip_address).await?);
        Ok(())
    }
}

pub struct ArtifactClientInstance {
    ip_address: Ipv6Addr,
    base_url: String,
    client: reqwest::Client,
}

impl ArtifactClientInstance {
    async fn new(if_info: &InterfaceInfo, ip_address: Ipv6Addr) -> anyhow::Result<Self> {
        debug!("creating client");
        let client = reqwest::Client::builder()
            .interface(&if_info.if_name)
            .build()?;

        Ok(Self {
            ip_address,
            base_url: format!("http://[{}]:{}", ip_address, ArtifactClient::PORT),
            client,
        })
    }

    #[instrument(skip_all, "artifact_client/download_firmware")]
    pub async fn download_firmware(&self, target: impl AsRef<Path>) -> anyhow::Result<()> {
        let url = format!("{}/firmware", self.base_url);
        info!("download_firmware: {url} -> {}", target.as_ref().display());

        let response = self.client.get(url).send().await?;
        let mut input = response.bytes_stream();

        let file = tokio::fs::File::create(target).await?;
        let mut output = tokio::io::BufWriter::new(file);

        while let Some(chunk) = input.next().await {
            output.write_all_buf(&mut chunk?).await?;
        }

        Ok(())
    }

    #[instrument(skip_all, "artifact_client/upload_file")]
    pub async fn upload_file(&self, source: impl AsRef<Path>) -> anyhow::Result<()> {
        let url = format!("{}/upload_file", self.base_url);

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
