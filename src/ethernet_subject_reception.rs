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
use anyhow::{anyhow, bail};
use async_trait::async_trait;
use pnet::datalink::{self, Channel::Ethernet, Config};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::task::{yield_now, JoinSet};
use tracing::{debug, error, info, warn};

/// Observer trait for handling specific Ethernet frame types
#[async_trait]
pub trait EthernetFrameObserver: Send + Sync + 'static {
    async fn on_frame(
        &self,
        interface_mac: MacAddr,
        frame: &[u8],
        source_mac: MacAddr,
        destination_mac: MacAddr,
    );
    fn get_ethertype(&self) -> u16;
}

/// Subject that receives Ethernet frames and notifies subscribed observers
#[derive(Default)]
pub struct EthernetReceiver {
    join_set: JoinSet<()>,
    observers: HashMap<u16, Sender<EthernetMessage>>,
}

struct EthernetMessage {
    interface_mac: MacAddr,
    ether_type: u16,
    payload: Vec<u8>,
    source_mac: MacAddr,
    destination_mac: MacAddr,
}

impl EthernetReceiver {
    /// **Create a new `EthernetReceiver`**
    pub fn new() -> Self {
        Self::default()
    }

    /// **Subscribe an observer**, avoiding duplicate subscriptions for the same `EtherType`
    pub fn subscribe(&mut self, observer: Arc<impl EthernetFrameObserver>) {
        let ether_type = observer.get_ethertype();
        debug!("Trying to subscribe observer for EtherType: 0x{ether_type:04X}");

        // Si ya hay un canal para ese ethertype, no duplicamos suscripciones
        let observer_entry = match self.observers.entry(ether_type) {
            Entry::Occupied(_) => {
                warn!("Observer for EtherType 0x{ether_type:04X} is already subscribed — skipping duplicate");
                return;
            }
            Entry::Vacant(e) => e,
        };

        let (observer_tx, mut observer_rx) = tokio::sync::mpsc::channel(1000);
        observer_entry.insert(observer_tx);

        self.join_set.spawn(async move {
            debug!("Observer task started for EtherType: 0x{:04X}", ether_type);

            while let Some(message) = observer_rx.recv().await {
                debug!(
                    interface_mac = ?message.interface_mac,
                    source_mac = ?message.source_mac,
                    destination_mac = ?message.destination_mac,
                    frame_length = message.payload.len(),
                    "Observer received frame"
                );

                observer
                    .on_frame(
                        message.interface_mac,
                        &message.payload,
                        message.source_mac,
                        message.destination_mac,
                    )
                    .await;

                // TODO this looks like a "magic delay" workaround and
                //  should be properly fixed on the reassembler side

                // To avoid situation when cmdu part with flag end
                // is processed before first one
                // yield will casue that reassembler is triggered for with
                // respect to the arrival of packets.
                yield_now().await;
            }
        });
    }

    /// **Start receiving Ethernet frames**
    pub fn run(mut self, interface_name: &str) -> anyhow::Result<JoinSet<()>> {
        info!("Starting EthernetReceiver on interface: {}", interface_name);

        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| anyhow!("Interface not found: {interface_name}"))?;

        let interface_mac = interface.mac.ok_or_else(|| {
            anyhow!("Failed to retrieve MAC address for interface {interface_name}")
        })?;

        info!("Listening on interface: {interface_name} (MAC: {interface_mac})");
        // Since we spawn a blocking task, we need to have an opportunity
        // to act on shutdown signal, that's why 1 sec. timeout is used.
        let config = Config {
            read_timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        };

        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(128);
        let mut datalink_rx = match datalink::channel(&interface, config) {
            Ok(Ethernet(_, rx)) => rx,
            Ok(_) => bail!("Unsupported channel type"),
            Err(e) => bail!("Failed to create datalink channel: {e}"),
        };

        self.join_set.spawn_blocking(move || {
            info!("Listening for Ethernet frames...");
            while !notify_tx.is_closed() {
                let packet = match datalink_rx.next() {
                    Ok(e) => e,
                    Err(e) => {
                        error!("Error receiving Ethernet frame: {e:?}");
                        continue;
                    }
                };

                let Some(eth_packet) = EthernetPacket::new(packet) else {
                    error!("Failed to parse Ethernet frame.");
                    continue;
                };

                let message = EthernetMessage {
                    interface_mac,
                    ether_type: eth_packet.get_ethertype().0,
                    payload: eth_packet.payload().to_vec(),
                    source_mac: eth_packet.get_source(),
                    destination_mac: eth_packet.get_destination(),
                };

                debug!(
                    ethertype = format!("0x{:04X}", message.ether_type),
                    source_mac = ?message.source_mac,
                    destination_mac = ?message.destination_mac,
                    packet_length = eth_packet.packet().len(),
                    "Received Ethernet frame"
                );

                // Notify observers with interface MAC included
                if notify_tx.blocking_send(message).is_err() {
                    warn!("Packet dropped: failed to send to async observer handler");
                }
            }
        });

        // TODO this intermediate channel is not needed and can be removed
        self.join_set.spawn(async move {
            while let Some(message) = notify_rx.recv().await {
                let ether_type = message.ether_type;
                let Some(observer) = self.observers.get(&ether_type) else {
                    continue;
                };
                if observer.send(message).await.is_ok() {
                    debug!("Notified observer for EtherType: 0x{ether_type:04X}");
                } else {
                    error!("Failed to notify observer for EtherType: 0x{ether_type:04X}");
                }
            }
        });
        Ok(self.join_set)
    }
}
