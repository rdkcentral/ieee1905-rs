use crate::interface_manager::InterfaceInfo;
use pnet::datalink::MacAddr;

////////////////////////////////////////////////////////////////////////////////
#[derive(Debug)]
pub struct ArtifactExchangeClientFactory;

impl ArtifactExchangeClientFactory {
    ////////////////////////////////////////////////////////////////////////////////
    pub async fn new(if_info: InterfaceInfo) -> anyhow::Result<Self> {
        let _ = if_info;
        Ok(Self)
    }

    ////////////////////////////////////////////////////////////////////////////////
    pub fn start(
        &self,
        remote_mac_address: MacAddr,
        base_url: &str,
    ) -> anyhow::Result<ArtifactExchangeClient> {
        let _ = (remote_mac_address, base_url);
        Ok(ArtifactExchangeClient)
    }
}

////////////////////////////////////////////////////////////////////////////////
#[derive(Debug)]
pub struct ArtifactExchangeClient;
