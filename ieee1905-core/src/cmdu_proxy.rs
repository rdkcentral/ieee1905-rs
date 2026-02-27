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
use crate::al_sap::AlServiceAccessPoint;
use crate::cmdu::TLV;
use crate::cmdu_codec::*;
use crate::ethernet_subject_transmission::EthernetSender;
use crate::interface_manager::get_mac_address_by_interface;
use crate::tlv_cmdu_codec::TLVTrait;
use crate::topology_manager::{Ieee1905Node, Role, TopologyDatabase, UpdateType};
use crate::SDU;
use crate::{next_task_id, MessageIdGenerator};
use pnet::datalink::MacAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, info_span, instrument, trace, warn, Instrument};

#[instrument(skip_all, name = "cmdu_discovery_transmission", fields(task = next_task_id()))]
pub async fn cmdu_topology_discovery_transmission_worker(
    interface: String,
    sender: Arc<EthernetSender>,
    message_id_generator: Arc<MessageIdGenerator>,
    local_al_mac_address: MacAddr,
    interface_mac_address: MacAddr,
) {
    let mut ticker = interval(Duration::from_secs(30)); // Creates a ticker that ticks every 5 seconds

    loop {
        ticker.tick().await; // Wait for the next tick before executing the loop body

        let message_id = message_id_generator.next_id();
        trace!(interface = %interface, message_id = message_id, "Creating CMDU Topology Discovery");

        let payload = [
            TLV::from(AlMacAddress {
                al_mac_address: local_al_mac_address,
            }),
            TLV::from(MacAddress {
                mac_address: interface_mac_address,
            }),
            TLV::from(EndOfMessage),
        ];

        // Construct CMDU
        let cmdu_topology_discovery = CMDU {
            message_version: MessageVersion::Version2013.to_u8(),
            reserved: 0,
            message_type: CMDUType::TopologyDiscovery.to_u16(),
            message_id,
            fragment: 0,
            flags: 0x80,
            payload: payload.iter().flat_map(TLV::serialize).collect(),
        };

        let serialized_cmdu = cmdu_topology_discovery.serialize();
        debug!(
            message_id = message_id,
            ?serialized_cmdu,
            "Serialized CMDU for Topology Discovery"
        );

        let destination_mac = MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x13); // IEEE 1905 Control Multicast Address
        let ethertype = 0x893A;

        match sender
            .enqueue_frame(
                destination_mac,
                interface_mac_address,
                ethertype,
                serialized_cmdu,
            )
            .await
        {
            Err(e) => {
                error!(message_id = message_id, "Failed to send CMDU: {}", e);
            }
            Ok(()) => {
                info!(interface = %interface, message_id = message_id, "CMDU Topology Discovery sent successfully");
            }
        }
    }
}

pub async fn cmdu_topology_query_transmission(
    interface: String,
    sender: Arc<EthernetSender>,
    message_id_generator: Arc<MessageIdGenerator>,
    local_al_mac_address: MacAddr,
    remote_al_mac_address: MacAddr,
    interface_mac_address: MacAddr,
) {
    tokio::spawn(
        async move {
            let message_id = message_id_generator.next_id();
            debug!(
                interface = %interface,
                message_id = message_id,
                "Creating CMDU Topology Query"
            );

            // Retrieve device data from the topology database
            let topology_db = TopologyDatabase::get_instance(local_al_mac_address, &interface);
            let Some(node) = topology_db.get_device(remote_al_mac_address).await else {
                debug!(
                    "Could not find node in topology database for AL_MAC={}",
                    remote_al_mac_address
                );
                return;
            };

            // Clone the device data (without modifying metadata)
            let device_data = node.device_data.clone();

            // **Retrieve Destination MAC Address**
            let destination_mac = device_data.destination_frame_mac;
            let local_role = topology_db.get_local_role().await;

            // Define TLVs
            let payload = [
                Some(TLV::from(AlMacAddress {
                    al_mac_address: local_al_mac_address,
                })),
                Some(TLV::from(VendorSpecificInfo {
                    oui: COMCAST_OUI,
                    vendor_data: COMCAST_QUERY_TAG.to_vec(),
                })),
                if let Some(Role::Registrar) = local_role {
                    Some(TLV::from(MultiApProfile::Profile3))
                } else {
                    None
                },
                Some(TLV::from(EndOfMessage)),
            ];

            // Construct CMDU
            let cmdu_topology_query = CMDU {
                message_version: MessageVersion::Version2013.to_u8(),
                reserved: 0,
                message_type: CMDUType::TopologyQuery.to_u16(),
                message_id,
                fragment: 0,
                flags: 0x80,
                payload: payload.iter().flatten().flat_map(TLV::serialize).collect(),
            };

            let serialized_cmdu = cmdu_topology_query.serialize();
            debug!(
                message_id = message_id,
                ?serialized_cmdu,
                "Serialized CMDU for Topology Query"
            );

            let source_mac = interface_mac_address;
            let ethertype = 0x893A; // IEEE 1905 EtherType

            // Send the CMDU via EthernetSender
            match sender
                .enqueue_frame(destination_mac, source_mac, ethertype, serialized_cmdu)
                .await
            {
                Err(e) => {
                    error!(
                        message_id = message_id,
                        "Failed to send CMDU Topology Query: {}", e
                    );
                }
                Ok(()) => {
                    debug!(
                        interface = %interface,
                        message_id = message_id,
                        al_mac = %local_al_mac_address,
                        "CMDU Topology Query sent successfully"
                    );

                    // **Update the node's state to `QUERY_SENT` in the topology database**
                    topology_db
                        .update_ieee1905_topology(
                            device_data.clone(),
                            UpdateType::QuerySent,
                            Some(message_id),
                            None,
                            None,
                        )
                        .await;
                    debug!(
                        "Updated topology database: AL_MAC={} set to QUERY_SENT",
                        remote_al_mac_address
                    );
                }
            }
        }
        .instrument(info_span!(parent: None, "cmdu_query_transmission", task = next_task_id())),
    );
}

pub fn cmdu_topology_response_transmission(
    interface: String,
    sender: Arc<EthernetSender>,
    local_al_mac_address: MacAddr,
    remote_al_mac_address: MacAddr,
    interface_mac_address: MacAddr,
    message_id: u16,
) {
    tokio::spawn(
        async move {
            //let message_id = message_id_generator.next_id();
            trace!(
                interface = %interface,
                "Creating CMDU Topology Response"
            );

            // Retrieve node information from the topology database
            let topology_db = TopologyDatabase::get_instance(local_al_mac_address, &interface);
            let Some(node) = topology_db.get_device(remote_al_mac_address).await else {
                warn!(
                    "Could not find node in topology database for AL_MAC={}",
                    remote_al_mac_address
                );
                return;
            };

            // Retrieve Forwarding MAC Address from Database
            let destination_mac = node.device_data.destination_frame_mac;
            let fragmentation = node.device_data.supported_fragmentation;

            // Building TLV payload
            let mut payload = vec![
                TLV::from(AlMacAddress {
                    al_mac_address: local_al_mac_address,
                }),
                TLV::from(VendorSpecificInfo {
                    oui: COMCAST_OUI,
                    vendor_data: COMCAST_QUERY_TAG.to_vec(),
                }),
                TLV::from(EndOfMessage),
            ];

            if let Err(e) = inject_topology_response_tlvs(&mut payload, &topology_db).await {
                return error!(%e, "failed to inject topo TLVs");
            }

            // Construct the CMDU
            let cmdu_topology_response = CMDU {
                message_version: MessageVersion::Version2013.to_u8(),
                reserved: 0,
                message_type: CMDUType::TopologyResponse.to_u16(),
                message_id,
                fragment: 0,
                flags: 0x80, // Not fragmented
                payload: payload.iter().flat_map(TLV::serialize).collect(),
            };

            let send_future = enqueue_fragmented_cmdu(
                &sender,
                destination_mac,
                interface_mac_address,
                cmdu_topology_response,
                fragmentation,
            );

            match send_future.await {
                Ok(_) => {
                    info!(
                        interface = %interface,
                        message_id = message_id,
                        "CMDU Topology Response sent successfully"
                    );

                    // **Update Topology Database to RESPONSE_SENT**

                    topology_db
                        .update_ieee1905_topology(
                            node.device_data.clone(),
                            UpdateType::ResponseSent,
                            None,
                            None,
                            None,
                        )
                        .await;

                    info!("Topology Database updated: AL_MAC={local_al_mac_address} set to ResponseSent");
                }
                Err(e) => error!(
                    message_id = message_id,
                    "Failed to send CMDU Topology Response: {e}",
                ),
            }
        }
            .instrument(info_span!(parent: None, "cmdu_response_transmission", task = next_task_id())),
    );
}

async fn inject_topology_response_tlvs(
    vec: &mut Vec<TLV>,
    db: &TopologyDatabase,
) -> anyhow::Result<()> {
    let Some(end_of_message_tlv) = vec.pop() else {
        anyhow::bail!("EndOfMessage TLV was not found");
    };

    if end_of_message_tlv.tlv_type != EndOfMessage::TYPE.to_u8() {
        vec.push(end_of_message_tlv);
        anyhow::bail!("TLV list doesn't end with EndOfMessage");
    }

    let filtered_types = [
        DeviceInformation::TYPE.to_u8(),
        DeviceBridgingCapability::TYPE.to_u8(),
        Ieee1905NeighborDevice::TYPE.to_u8(),
        NonIeee1905NeighborDevices::TYPE.to_u8(),
    ];
    vec.retain(|e| !filtered_types.contains(&e.tlv_type));

    // injecting DeviceInformation
    vec.push({
        let local_interfaces = db.local_interface_list.read().await;
        let local_interfaces = local_interfaces.iter().flatten().map(|e| LocalInterface {
            mac_address: e.mac,
            media_type: e.media_type,
            special_info: e.media_type_extra.clone(),
        });

        TLV::from(DeviceInformation::new(
            db.al_mac_address,
            local_interfaces.collect(),
        ))
    });

    // injecting DeviceBridgingCapability
    {
        let mut by_bridge = HashMap::<u32, Vec<MacAddr>>::new();

        let local_interfaces = db.local_interface_list.read().await;
        for interface in local_interfaces.iter().flatten() {
            if let Some(tuple) = interface.bridging_tuple {
                by_bridge.entry(tuple).or_default().push(interface.mac);
            }
        }

        let mut tuples = Vec::new();
        for tuple in by_bridge.into_values() {
            if tuple.len() > 1 {
                tuples.push(BridgingTuple {
                    bridging_mac_count: tuple.len() as u8,
                    bridging_mac_list: tuple,
                });
            }
        }

        if !tuples.is_empty() {
            vec.push(TLV::from(DeviceBridgingCapability {
                bridging_tuples_count: tuples.len() as u8,
                bridging_tuples_list: tuples,
            }));
        }
    }

    // injecting Ieee1905NeighborDevice
    {
        let local_mac_address = db.get_forwarding_interface_mac().await;
        let nodes = db.nodes.read().await;

        let neighborhood_list = Vec::from_iter(nodes.iter().filter_map(|(mac, node)| {
            if *mac == db.al_mac_address {
                return None; // Don't include your self as a neighbor
            }
            Some(IEEE1905Neighbor {
                neighbor_al_mac: *mac,
                neighbor_flags: match node.metadata.lldp_neighbor.is_some() {
                    true => 0b1000_0000,
                    false => 0b0000_0000,
                },
            })
        }));

        if !neighborhood_list.is_empty() {
            vec.push(TLV::from(Ieee1905NeighborDevice {
                local_mac_address,
                neighborhood_list,
            }));
        }
    }

    // injecting NonIeee1905NeighborDevices
    {
        let local_interfaces = db.local_interface_list.read().await;
        vec.extend(local_interfaces.iter().flatten().map(|e| {
            let interfaces = e.non_ieee1905_neighbors.as_deref();
            TLV::from(NonIeee1905NeighborDevices {
                local_mac_address: e.mac,
                neighborhood_list: interfaces.unwrap_or_default().to_owned(),
            })
        }));
    }

    vec.push(end_of_message_tlv);
    Ok(())
}

pub fn cmdu_topology_notification_transmission(
    interface: String,
    sender: Arc<EthernetSender>,
    message_id_generator: Arc<MessageIdGenerator>,
    local_al_mac_address: MacAddr,
    forwarding_interface_mac: MacAddr,
) {
    tokio::spawn(
        async move {
            let message_id = message_id_generator.next_id();
            trace!(
                interface = %interface,
                message_id = message_id,
                "Creating CMDU Topology Notification"
            );

            info!(
                "Updated topology database: MSGId={} set to NotificationSent",
                message_id
            );

            let topology_db = TopologyDatabase::get_instance(local_al_mac_address, &interface);

            let payload = [
                TLV::from(AlMacAddress {
                    al_mac_address: local_al_mac_address,
                }),
                TLV::from(VendorSpecificInfo {
                    oui: COMCAST_OUI,
                    vendor_data: COMCAST_QUERY_TAG.to_vec(),
                }),
                TLV::from(EndOfMessage),
            ];

            // Construct the Topology Notification CMDU
            let cmdu_topology_notification = CMDU {
                message_version: MessageVersion::Version2013.to_u8(),
                reserved: 0,
                message_type: CMDUType::TopologyNotification.to_u16(),
                message_id,
                fragment: 0,
                flags: 0x80, // Not fragmented
                payload: payload.iter().flat_map(TLV::serialize).collect(),
            };

            // Serialize CMDU
            let serialized_cmdu = cmdu_topology_notification.serialize();
            debug!(
                message_id = message_id,
                ?serialized_cmdu,
                "Serialized CMDU for Topology Notification"
            );

            // Set IEEE 1905 multicast destination MAC
            let destination_mac = MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x13);
            let source_mac = forwarding_interface_mac;
            let ethertype = 0x893A; // IEEE 1905 EtherType

            // Send the CMDU via EthernetSender
            match sender
                .send_frame(destination_mac, source_mac, ethertype, serialized_cmdu)
                .await
            {
                Ok(()) => {
                    info!(
                        interface = %interface,
                        message_id = message_id,
                        "CMDU Topology Notification sent successfully"
                    );
                    topology_db.handle_notification_sent().await;
                }
                Err(e) => error!(
                    message_id = message_id,
                    "Failed to send CMDU Topology Notification: {}", e
                ),
            }
        }
        .instrument(
            info_span!(parent: None, "cmdu_notification_transmission", task = next_task_id()),
        ),
    );
}

#[instrument(skip_all, name = "cmdu_link_metric_query_transmission", fields(task = next_task_id()))]
pub async fn cmdu_link_metric_query_transmission_worker(
    sender: Arc<EthernetSender>,
    message_id_generator: Arc<MessageIdGenerator>,
    local_interface_mac: MacAddr,
    destination_mac: MacAddr,
    cancellation_token: CancellationToken,
) {
    let mut ticker = interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = ticker.tick() => (),
            _ = cancellation_token.cancelled() => return,
        }

        let message_id = message_id_generator.next_id();
        debug!(%destination_mac, message_id, "Creating CMDU");

        let payload = [
            TLV::from(LinkMetricQuery {
                neighbor_type: LinkMetricQuery::NEIGHBOR_ALL,
                neighbor_mac: None,
                requested_metrics: LinkMetricQuery::METRIC_TX_RX,
            }),
            TLV::from(EndOfMessage),
        ];

        let cmdu = CMDU {
            message_version: MessageVersion::Version2013.to_u8(),
            reserved: 0,
            message_type: CMDUType::LinkMetricQuery.to_u16(),
            message_id,
            fragment: 0,
            flags: 0x80,
            payload: payload.iter().flat_map(TLV::serialize).collect(),
        };

        let cmdu_bytes = cmdu.serialize();
        trace!(%destination_mac, message_id, ?cmdu_bytes, "CMDU serialized");
        debug!(%destination_mac, message_id, "Sending CMDU");

        let result = sender
            .enqueue_frame(
                destination_mac,
                local_interface_mac,
                EthernetSender::ETHER_TYPE,
                cmdu_bytes,
            )
            .await;

        match result {
            Ok(()) => info!(%destination_mac, message_id, "CMDU sent successfully"),
            Err(e) => error!(%destination_mac, message_id, %e, "Failed to send CMDU"),
        }
    }
}

#[instrument(skip_all, name = "cmdu_link_metric_response_transmission", fields(task = next_task_id()))]
pub async fn cmdu_link_metric_response_transmission(
    interface: String,
    sender: Arc<EthernetSender>,
    message_id: u16,
    local_al_mac_address: MacAddr,
    remote_al_mac_address: MacAddr,
    include_rx: bool,
    include_tx: bool,
    neighbors: Vec<Ieee1905Node>,
) {
    debug!(
        %interface,
        message_id,
        "Creating CMDU Link Metric Response"
    );

    // Retrieve device data from the topology database
    let topology_db = TopologyDatabase::get_instance(local_al_mac_address, &interface);
    let Some(node) = topology_db.get_device(remote_al_mac_address).await else {
        debug!("Could not find node in topology database for AL_MAC={remote_al_mac_address}");
        return;
    };

    let source_mac = topology_db.get_forwarding_interface_mac().await;
    let target_mac = node.device_data.destination_frame_mac;
    let fragmentation = node.device_data.supported_fragmentation;

    let mut tlvs = Vec::new();
    for neighbor in neighbors {
        let local_interfaces = topology_db.local_interface_list.read().await;
        let local_interfaces = local_interfaces.as_deref().unwrap_or_default();
        let Some(interface) = local_interfaces.iter().find(|e| e.mac == source_mac) else {
            warn!("Could not find local interface with mac {source_mac}");
            continue;
        };

        let link_stats = interface.link_stats.unwrap_or_default();
        let neighbour_if1 = neighbor.device_data.destination_mac;
        let neighbour_if2 = neighbor.device_data.destination_frame_mac;
        let neighbour_if = neighbour_if1.unwrap_or(neighbour_if2);

        fn to_u16_sat(value: u64) -> u16 {
            u16::try_from(value).unwrap_or(u16::MAX)
        }

        fn to_u32_sat(value: u64) -> u32 {
            u32::try_from(value).unwrap_or(u32::MAX)
        }

        if include_rx {
            let pair = LinkMetricRxPair {
                receiver_interface_mac: interface.mac,
                neighbour_interface_mac: neighbour_if,
                interface_type: interface.media_type,
                packet_errors: to_u32_sat(link_stats.rx_errors),
                transmitted_packets: to_u32_sat(link_stats.rx_packets),
                rssi: interface.signal_strength_dbm.unwrap_or(0xffu8 as i8),
            };

            tlvs.push(TLV::from(LinkMetricRx {
                source_al_mac: local_al_mac_address,
                neighbour_al_mac: neighbor.device_data.al_mac,
                interface_pairs: vec![pair],
            }));
        }

        if include_tx {
            let phy_rate = to_u16_sat(interface.phy_rate.unwrap_or_default() / 1_000_000);
            let pair = LinkMetricTxPair {
                receiver_interface_mac: interface.mac,
                neighbour_interface_mac: neighbour_if,
                interface_type: interface.media_type,
                has_more_ieee802_bridges: interface.bridging_flag.into(),
                packet_errors: to_u32_sat(link_stats.tx_errors),
                transmitted_packets: to_u32_sat(link_stats.tx_packets),
                mac_throughput_capacity: phy_rate,
                link_availability: interface.link_availability.unwrap_or(100).into(),
                phy_rate,
            };

            tlvs.push(TLV::from(LinkMetricTx {
                source_al_mac: local_al_mac_address,
                neighbour_al_mac: neighbor.device_data.al_mac,
                interface_pairs: vec![pair],
            }));
        }
    }

    // End of message TLV
    tlvs.push(TLV::from(EndOfMessage));

    // Construct CMDU
    let cmdu = CMDU {
        message_version: MessageVersion::Version2013.to_u8(),
        reserved: 0,
        message_type: CMDUType::LinkMetricResponse.to_u16(),
        message_id,
        fragment: 0,
        flags: 0x80,
        payload: tlvs.iter().flat_map(TLV::serialize).collect(),
    };

    match enqueue_fragmented_cmdu(&sender, target_mac, source_mac, cmdu, fragmentation).await {
        Ok(_) => debug!(
            interface,
            message_id,
            al_mac = %local_al_mac_address,
            "CMDU Link Metric Response sent successfully",
        ),
        Err(e) => error!(
            interface,
            message_id,
            al_mac = %local_al_mac_address,
            "Failed to send CMDU Link Metric Response: {e}",
        ),
    }
}

pub fn cmdu_from_sdu_transmission(interface: String, sender: Arc<EthernetSender>, sdu: SDU) {
    tokio::spawn(async move {
        if !AlServiceAccessPoint::is_connected_and_enabled().await {
            return info!("AlSap is not active, ignoring SDU");
        }

        trace!(?sdu, "Parsing CMDU from SDU payload");
        let source_al_mac = sdu.source_al_mac_address;
        let destination_al_mac = sdu.destination_al_mac_address;
        let fragmentation;

        match CMDU::parse(&sdu.payload) {
            Ok((_, mut cmdu)) => {
                let topology_db = TopologyDatabase::get_instance(source_al_mac, &interface);
                let destination_mac = if sdu.destination_al_mac_address == IEEE1905_CONTROL_ADDRESS {
                    trace!("Parsing CMDU from SDU payload destination mac address is IEEE1905_CONTROL_ADDRESS");
                    fragmentation = CMDUFragmentation::default();
                    IEEE1905_CONTROL_ADDRESS
                } else {
                    trace!("Acquiry topology database for source al mac address {source_al_mac}");
                    trace!("Searching for destination {destination_al_mac} in topology database");

                    let Some(node) = topology_db.get_device(sdu.destination_al_mac_address).await else {
                        return warn!("No destination_mac found for AL-MAC {destination_al_mac}");
                    };

                    fragmentation = node.device_data.supported_fragmentation;
                    node.device_data.destination_frame_mac
                };

                let source_mac = match get_mac_address_by_interface(&interface) {
                    Some(mac) => mac,
                    None => {
                        return warn!("Interface {} not found or has no MAC address", interface);
                    }
                };

                if cmdu.message_type == CMDUType::TopologyResponse.to_u16() {
                    let Ok(mut tlvs) = cmdu.get_tlvs() else {
                        return error!("Failed to parse topo response TLVs");
                    };
                    if let Err(e) = inject_topology_response_tlvs(&mut tlvs, &topology_db).await {
                        return error!(%e, "Failed to inject topo response TLVs");
                    }
                    debug!("injecting topology response TLVs");
                    cmdu.payload = tlvs.iter().flat_map(TLV::serialize).collect();
                    trace!(?cmdu, "injected topology response TLVs");
                }

                if let Err(e) = enqueue_fragmented_cmdu(&sender, destination_mac, source_mac, cmdu, fragmentation).await {
                    error!("Failed to send CMDU: {e}");
                }
            }
            Err(_) => {
                error!("Failed to parse CMDU from SDU payload!");
            }
        }
    }.instrument(info_span!(parent: None, "cmdu_from_sdu_transmission", task = next_task_id())));
}

async fn enqueue_fragmented_cmdu(
    sender: &EthernetSender,
    target_mac: MacAddr,
    source_mac: MacAddr,
    cmdu: CMDU,
    fragmentation: CMDUFragmentation,
) -> anyhow::Result<()> {
    let fragments = cmdu.fragment(fragmentation, EthernetSender::ETHER_MTU_SIZE)?;
    for fragment in fragments {
        let serialized = fragment.serialize();
        trace!(
            target = %target_mac,
            source = %source_mac,
            frag = ?fragmentation,
            bytes = ?serialized,
            "Sending CMDU fragment"
        );

        let ether_type = EthernetSender::ETHER_TYPE;
        sender
            .enqueue_frame(target_mac, source_mac, ether_type, serialized)
            .await?;

        debug!(fragment = fragment.fragment, "CMDU fragment sent")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology_manager::{Ieee1905DeviceData, Ieee1905LocalInterface};

    #[tokio::test]
    async fn test_inject_topology_response_tlvs_failure() {
        let db = TopologyDatabase::new(MacAddr::broadcast(), "if_name".to_string());
        let response = inject_topology_response_tlvs(&mut Vec::new(), &db).await;
        assert!(response.is_err());
    }

    #[tokio::test]
    async fn test_inject_topology_response_tlvs_clear() {
        let local_interface = LocalInterface::new(
            MacAddr::zero(),
            MediaType::default(),
            MediaTypeSpecialInfo::Other(vec![]),
        );

        let mut vec = vec![
            TLV::from(DeviceInformation::new(
                MacAddr::broadcast(),
                vec![local_interface.clone(), local_interface.clone()],
            )),
            TLV::from(DeviceBridgingCapability {
                bridging_tuples_count: 0,
                bridging_tuples_list: vec![],
            }),
            TLV::from(Ieee1905NeighborDevice {
                local_mac_address: Default::default(),
                neighborhood_list: vec![],
            }),
            TLV::from(NonIeee1905NeighborDevices {
                local_mac_address: Default::default(),
                neighborhood_list: vec![],
            }),
            TLV::from(EndOfMessage),
        ];

        let db = TopologyDatabase::new(MacAddr::broadcast(), "if_name".to_string());
        let response = inject_topology_response_tlvs(&mut vec, &db).await;
        assert!(response.is_ok());
        assert_eq!(vec.len(), 2);
    }

    #[tokio::test]
    async fn test_inject_topology_response_tlvs() {
        let mut if1 = Ieee1905LocalInterface::default();
        if1.data.mac = MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x01);
        if1.data.bridging_flag = true;
        if1.data.bridging_tuple = Some(1);
        if1.data.non_ieee1905_neighbors = Some(vec![
            MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x02, 0x01),
            MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x02, 0x02),
            MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x02, 0x03),
        ]);

        let mut if2 = Ieee1905LocalInterface::default();
        if2.data.mac = MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x02);
        if2.data.bridging_flag = true;
        if2.data.bridging_tuple = Some(1);

        let db = TopologyDatabase::new(MacAddr::broadcast(), "if_name".to_string());
        *db.local_interface_list.write().await = Some(vec![if1.clone(), if2.clone()]);

        let mut device = Ieee1905DeviceData::default();
        device.al_mac = MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x01, 0x01);
        db.update_ieee1905_topology(
            device.clone(),
            UpdateType::DiscoveryReceived,
            None,
            None,
            None,
        )
        .await;

        let mut vec = vec![TLV::from(EndOfMessage)];
        let response = inject_topology_response_tlvs(&mut vec, &db).await;
        assert!(response.is_ok());

        let Some(device_info) = DeviceInformation::find(&vec) else {
            panic!();
        };
        assert_eq!(device_info.al_mac_address, db.al_mac_address);
        assert_eq!(device_info.local_interface_count, 2);

        let Some(bridging_capability) = DeviceBridgingCapability::find(&vec) else {
            panic!();
        };
        assert_eq!(bridging_capability.bridging_tuples_list.len(), 1);
        assert_eq!(
            bridging_capability.bridging_tuples_list[0].bridging_mac_list,
            vec![if1.mac, if2.mac],
        );

        let Some(ieee1905_list) = Ieee1905NeighborDevice::find(&vec) else {
            panic!();
        };
        assert_eq!(ieee1905_list.local_mac_address, *db.local_mac.read().await);
        assert_eq!(ieee1905_list.neighborhood_list.len(), 1);
        assert_eq!(
            ieee1905_list.neighborhood_list[0].neighbor_al_mac,
            device.al_mac
        );

        let Some(non_ieee1905_list) = NonIeee1905NeighborDevices::find(&vec) else {
            panic!();
        };
        assert_eq!(non_ieee1905_list.local_mac_address, if1.mac);
        assert_eq!(non_ieee1905_list.neighborhood_list.len(), 3);
        assert_eq!(
            non_ieee1905_list.neighborhood_list,
            if1.non_ieee1905_neighbors.as_deref().unwrap_or_default()
        );

        let Some(last) = vec.last() else {
            panic!();
        };
        assert_eq!(last.tlv_type, EndOfMessage::TYPE.to_u8());
    }
}
