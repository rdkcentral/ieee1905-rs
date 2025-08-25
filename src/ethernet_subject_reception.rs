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
use async_trait::async_trait;
use pnet::datalink::{self, Channel::Ethernet, Config};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::task::{self, yield_now};
use tokio_tasker::Tasker;
use tracing::{debug, error, info, warn};
use crate::task_registry::TASK_REGISTRY;

/// Observer trait for handling specific Ethernet frame types
#[async_trait]
pub trait EthernetFrameObserver: Send + Sync {
    async fn on_frame(&self, interface_mac: MacAddr, frame: &[u8], source_mac: MacAddr, destination_mac: MacAddr);
    fn get_ethertype(&self) -> u16;
}
type MacAddrHashMap = HashMap<u16, Vec<mpsc::Sender<(MacAddr, Vec<u8>, MacAddr, MacAddr)>>>;
type ChannelType = (MacAddr, u16, Vec<u8>, MacAddr, MacAddr);
/// Subject that receives Ethernet frames and notifies subscribed observers
pub struct EthernetReceiver {
    observers: Arc<Mutex<MacAddrHashMap>>,
    rx_channel: mpsc::Sender<ChannelType>,
}


impl EthernetReceiver {
    /// **Create a new `EthernetReceiver`**
    pub fn new() -> Self {
        let (tx, mut rx): (mpsc::Sender<ChannelType>, mpsc::Receiver<ChannelType>) = mpsc::channel(100);

        let observers: Arc<Mutex<MacAddrHashMap>>
            = Arc::new(Mutex::new(HashMap::new()));

        let observers_clone = Arc::clone(&observers);

        // Spawn an async task to notify observers
        task::spawn(async move {
            while let Some((interface_mac, ethertype, frame, source_mac, destination_mac)) = rx.recv().await {
                let obs = observers_clone.lock().await;

                if let Some(observer_list) = obs.get(&ethertype) {
                    for observer_tx in observer_list {
                        if observer_tx.send((interface_mac, frame.clone(), source_mac, destination_mac)).await.is_err() {
                            error!("Failed to notify observer for EtherType: 0x{:04X}", ethertype);
                        } else {
                            debug!("Notified observer for EtherType: 0x{:04X}", ethertype);
                        }
                    }
                }
            }
        });

        Self {
            observers,
            rx_channel: tx,
        }
    }

   /// **Subscribe an observer**, avoiding duplicate subscriptions for the same `EtherType`
    pub async fn subscribe<O: EthernetFrameObserver + 'static>(&self, observer: Arc<O>) {
        let ethertype = observer.get_ethertype();
        debug!("Trying to subscribe observer for EtherType: 0x{:04X}", ethertype);

        let mut obs = self.observers.lock().await;

        // Si ya hay un canal para ese ethertype, no duplicamos suscripciones
        if obs.contains_key(&ethertype) {
            warn!("Observer for EtherType 0x{:04X} is already subscribed — skipping duplicate", ethertype);
            return;
        }

        let (tx, mut rx) = mpsc::channel(1000);
        obs.insert(ethertype, vec![tx]);

        // Spawn async task to process received frames
        let observer_clone = Arc::clone(&observer);
        let task_handle = task::spawn(async move {
            debug!("Observer task started for EtherType: 0x{:04X}", ethertype);
            while let Some((interface_mac, frame, source_mac, destination_mac)) = rx.recv().await {
                debug!(
                    interface_mac = ?interface_mac,
                    source_mac = ?source_mac,
                    destination_mac = ?destination_mac,
                    frame_length = frame.len(),
                    "Observer received frame"
                );
                observer_clone.on_frame(interface_mac, &frame, source_mac, destination_mac).await;
                // To avoid situation when cmdu part with flag end
                // is processed before first one
                // yield will casue that reassembler is triggered for with
                // respect to the arrival of packets.
                yield_now().await;
            }
        });
        TASK_REGISTRY.lock().await.push(task_handle);
    }



    /// **Start receiving Ethernet frames**
    pub async fn run(&self, interface_name: &str, tasker: Tasker) {
        info!("Starting EthernetReceiver on interface: {}", interface_name);

        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .expect("ERROR: Interface not found");

        let interface_mac = interface.mac.unwrap_or_else(|| {
            panic!("ERROR: Failed to retrieve MAC address for interface {interface_name}")
        });

        info!("Listening on interface: {} (MAC: {})", interface_name, interface_mac);
        // Since we spawn a blocking task, we need to have an opportunity
        // to act on shutdown signal, that's why 1 sec. timeout is used.
        let config = Config { read_timeout: Some(Duration::from_secs(1)), ..Default::default() };
        let (_tx, rx) = match datalink::channel(&interface, config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("ERROR: Unsupported channel type"),
            Err(e) => panic!("ERROR: Failed to create datalink channel: {e}"),
        };

        let tx_channel = self.rx_channel.clone();

                task::spawn_blocking(move || {
                    info!("Listening for Ethernet frames...");
                    let mut rx = rx;

                    loop {
                        if tasker.stopper().is_stopped() {
                            debug!("Stopping loop due tu tasker signal");
                            tasker.finish();
                            break;
                        }
                        match rx.next() {
                            Ok(packet) => {
                                if let Some(eth_packet) = EthernetPacket::new(packet) {
                                    let ethertype = eth_packet.get_ethertype().0;
                                    let payload = eth_packet.payload().to_vec();
                                    let source_mac = eth_packet.get_source();
                                    let destination_mac = eth_packet.get_destination();

                                    debug!(
                                        ethertype = format!("0x{:04X}", ethertype),
                                        source_mac = ?source_mac,
                                        destination_mac = ?destination_mac,
                                        packet_length = eth_packet.packet().len(),
                                        "Received Ethernet frame"
                                    );

                            // Notify observers with interface MAC included
                            if tx_channel.blocking_send((interface_mac, ethertype, payload, source_mac, destination_mac)).is_err() {
                                        warn!("Packet dropped: failed to send to async observer handler (queue full?)");
                                    }
                                } else {
                                    error!("Failed to parse Ethernet frame.");
                                }
                            }
                            Err(e) => {error!("Error receiving Ethernet frame: {:?}", e);},
                        }
                    }
                });
    }
}

impl Default for EthernetReceiver {
    fn default() -> Self {
        Self::new()
    }
}
