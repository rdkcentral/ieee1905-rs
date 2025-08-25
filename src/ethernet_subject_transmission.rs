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

#![deny(warnings)]
// External crates
use pnet::datalink::MacAddr;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

// Standard library
use std::sync::Arc;
use crate::task_registry::TASK_REGISTRY;

#[derive(Debug, Clone)]
pub struct Frame {
    pub destination_mac: MacAddr,
    pub source_mac: MacAddr,
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

pub struct EthernetSender {
    tx_channel: mpsc::Sender<Frame>,
}

impl EthernetSender {
    /// **Creates a new `EthernetSender`**
    pub async fn new(interface_name: &str, interface_mutex: Arc<Mutex<()>>) -> Self {
        let (tx, mut rx): (mpsc::Sender<Frame>, mpsc::Receiver<Frame>) = mpsc::channel(100);

        let interface_name = interface_name.to_string();
        let interface_mutex_clone = Arc::clone(&interface_mutex);

        let task_handle =tokio::spawn(async move {
            info!(interface_name = %interface_name, "Async sender task initialized");

            let interfaces = pnet::datalink::interfaces();
            let interface = match interfaces.into_iter().find(|iface| iface.name == interface_name) {
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

                let _lock = interface_mutex_clone.lock().await;

                let mut buffer = vec![0u8; 14 + frame.payload.len()];
                buffer[..6].copy_from_slice(&frame.destination_mac.octets());
                buffer[6..12].copy_from_slice(&frame.source_mac.octets());
                buffer[12..14].copy_from_slice(&frame.ethertype.to_be_bytes());
                buffer[14..].copy_from_slice(&frame.payload);

                match tx.send_to(&buffer, None) {
                    Some(Ok(())) => debug!("Frame sent successfully"),
                    Some(Err(e)) => error!("Failed to send frame: {:?}", e),
                    None => warn!("No transmit descriptor available"),
                }
            }

            warn!("Async sender task exiting.");
        });
        TASK_REGISTRY.lock().await.push(task_handle);

        Self {
            tx_channel: tx,
        }
    }

    /// **Enqueues a frame for transmission**
    pub async fn send_frame(
        &self,
        destination_mac: MacAddr,
        source_mac: MacAddr,
        ethertype: u16,
        payload: &[u8],
    ) -> Result<(), String> {
        let frame = Frame {
            destination_mac,
            source_mac,
            ethertype,
            payload: payload.to_vec(),
        };

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
            .map_err(|e| format!("Failed to send frame to async sender task: {e}"))
    }
}
