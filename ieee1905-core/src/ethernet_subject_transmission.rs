/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
use crate::next_task_id;
use anyhow::anyhow;
use pnet::datalink::MacAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tracing::{debug, error, info, info_span, warn, Instrument};

#[derive(Debug)]
struct Frame {
    destination_mac: MacAddr,
    source_mac: MacAddr,
    ethertype: u16,
    payload: Vec<u8>,
    success_channel: Option<tokio::sync::oneshot::Sender<()>>,
}

pub struct EthernetSender {
    _join_set: JoinSet<()>,
    tx_channel: mpsc::Sender<Frame>,
}

impl EthernetSender {
    pub const ETHER_TYPE: u16 = 0x893A;
    pub const ETHER_MTU_SIZE: usize = 1500;

    /// **Creates a new `EthernetSender`**
    pub fn new(interface_name: &str, interface_mutex: Arc<Mutex<()>>) -> Self {
        let (tx, mut rx) = mpsc::channel::<Frame>(100);

        let interface_name = interface_name.to_string();

        let mut join_set = JoinSet::new();
        join_set.spawn(
            async move {
                info!(interface_name = %interface_name, "Async sender task initialized");

                let interfaces = pnet::datalink::interfaces();
                let interface = match interfaces
                    .into_iter()
                    .find(|iface| iface.name == interface_name)
                {
                    Some(iface) => iface,
                    None => {
                        error!(interface_name = %interface_name, "Interface not found");
                        return;
                    }
                };

                info!(interface_name = %interface.name, "Found network interface");

                let config = pnet::datalink::Config::default();
                let (mut tx, _rx) = match pnet::datalink::channel(&interface, config) {
                    Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => {
                        error!("Unsupported channel type");
                        return;
                    }
                    Err(e) => {
                        error!("Failed to create datalink channel: {}", e);
                        return;
                    }
                };

                debug!("Async sender task is processing frames...");

                while let Some(frame) = rx.recv().await {
                    debug!(
                        destination_mac = ?frame.destination_mac,
                        source_mac = ?frame.source_mac,
                        ethertype = format!("0x{:04X}", frame.ethertype),
                        payload_length = frame.payload.len(),
                        "Processing outgoing Ethernet frame"
                    );

                    let _lock = interface_mutex.lock().await;

                    let mut buffer = vec![0u8; 14 + frame.payload.len()];
                    buffer[..6].copy_from_slice(&frame.destination_mac.octets());
                    buffer[6..12].copy_from_slice(&frame.source_mac.octets());
                    buffer[12..14].copy_from_slice(&frame.ethertype.to_be_bytes());
                    buffer[14..].copy_from_slice(&frame.payload);

                    match tx.send_to(&buffer, None) {
                        Some(Ok(())) => {
                            if let Some(e) = frame.success_channel {
                                let _ = e.send(());
                            }
                            debug!("Frame sent successfully")
                        }
                        Some(Err(e)) => error!("Failed to send frame: {:?}", e),
                        None => warn!("No transmit descriptor available"),
                    }
                }

                warn!("Async sender task exiting.");
            }
            .instrument(info_span!(parent: None, "ethernet_sender", task = next_task_id())),
        );

        Self {
            _join_set: join_set,
            tx_channel: tx,
        }
    }

    /// Enqueues a frame for transmission and waits for it to be actually sent
    pub async fn send_frame(
        &self,
        destination_mac: MacAddr,
        source_mac: MacAddr,
        ethertype: u16,
        payload: Vec<u8>,
    ) -> anyhow::Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let frame = Frame {
            destination_mac,
            source_mac,
            ethertype,
            payload: payload.into(),
            success_channel: Some(tx),
        };
        self.enqueue_frame_internal(frame).await?;
        rx.await.map_err(|e| anyhow!("Failed to send frame: {e}"))
    }

    /// Enqueues a frame for transmission
    pub async fn enqueue_frame(
        &self,
        destination_mac: MacAddr,
        source_mac: MacAddr,
        ethertype: u16,
        payload: Vec<u8>,
    ) -> anyhow::Result<()> {
        let frame = Frame {
            destination_mac,
            source_mac,
            ethertype,
            payload,
            success_channel: None,
        };
        self.enqueue_frame_internal(frame).await
    }

    /// Enqueues a frame for transmission
    async fn enqueue_frame_internal(&self, frame: Frame) -> anyhow::Result<()> {
        debug!(
            destination_mac = ?frame.destination_mac,
            source_mac = ?frame.source_mac,
            ethertype = format!("0x{:04X}", frame.ethertype),
            payload_length = frame.payload.len(),
            "Enqueuing frame for transmission"
        );

        self.tx_channel
            .send(frame)
            .await
            .map_err(|e| anyhow!("Failed to send frame to async sender task: {e}"))?;
        Ok(())
    }
}
