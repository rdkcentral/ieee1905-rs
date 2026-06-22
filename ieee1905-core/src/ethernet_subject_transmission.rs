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
use crate::ethernet_subject_reception::AsyncSocket;
use crate::interface_manager::get_interface_info;
use crate::{next_task_id, spawn_join_set_named};
use anyhow::anyhow;
use pnet::datalink::MacAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use tracing::{debug, error, info, instrument, warn};

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

    ///////////////////////////////////////////////////////////////////////////
    pub fn new(interface_name: &str, interface_mutex: Arc<Mutex<()>>) -> Self {
        let (tx, rx) = mpsc::channel::<Frame>(100);

        let mut join_set = JoinSet::new();
        spawn_join_set_named(
            format!("eth_send/{interface_name}"),
            None,
            &mut join_set,
            Self::worker(interface_name.to_owned(), interface_mutex, rx),
        );

        Self {
            _join_set: join_set,
            tx_channel: tx,
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    #[instrument(
        skip_all,
        name = "ethernet_sender",
        fields(task = next_task_id(), if_name = interface_name),
    )]
    async fn worker(
        interface_name: String,
        interface_mutex: Arc<Mutex<()>>,
        mut rx: Receiver<Frame>,
    ) {
        info!(interface_name = %interface_name, "Async sender task initialized");

        let Some(if_info) = get_interface_info(&interface_name) else {
            error!(interface_name = %interface_name, "Interface not found");
            return;
        };

        let socket = match AsyncSocket::open(&if_info) {
            Ok(socket) => socket,
            Err(e) => {
                error!(interface_name = %interface_name, "Failed to open packet socket: {e}");
                return;
            }
        };

        debug!("Async sender task is processing frames...");

        let mut buffer = Vec::with_capacity(1500);
        while let Some(frame) = rx.recv().await {
            debug!(
                destination_mac = ?frame.destination_mac,
                source_mac = ?frame.source_mac,
                ethertype = format!("0x{:04X}", frame.ethertype),
                payload_length = frame.payload.len(),
                "Processing outgoing Ethernet frame"
            );

            buffer.clear();
            buffer.extend(frame.destination_mac.octets());
            buffer.extend(frame.source_mac.octets());
            buffer.extend(frame.ethertype.to_be_bytes());
            buffer.extend(frame.payload);

            // Create shared mutex for exclusive access to network interfaces for transmission
            let _lock = interface_mutex.lock().await;

            match socket.send(&buffer).await {
                Ok(_) => {
                    if let Some(e) = frame.success_channel {
                        let _ = e.send(());
                    }
                    debug!("Frame sent successfully")
                }
                Err(e) => error!("Failed to send frame: {e}"),
            }
        }

        warn!("Async sender task exiting.");
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
            payload,
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
