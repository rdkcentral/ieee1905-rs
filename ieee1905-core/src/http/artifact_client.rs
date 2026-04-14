use futures::StreamExt;
use std::net::SocketAddrV6;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use tracing::{info, instrument};

pub struct ArtifactClient {
    client: reqwest::Client,
    base_url: String,
}

impl ArtifactClient {
    pub fn new(if_name: &str, address: SocketAddrV6) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder().interface(if_name).build()?;
        Ok(Self {
            client,
            base_url: format!("http://[{}]:{}", address.ip(), address.port()),
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
