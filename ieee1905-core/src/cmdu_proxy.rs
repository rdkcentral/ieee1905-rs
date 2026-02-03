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
use crate::cmdu::TLV;
use crate::cmdu_codec::*;
use crate::ethernet_subject_transmission::EthernetSender;
use crate::interface_manager::get_mac_address_by_interface;
use crate::topology_manager::{
    Ieee1905Node, StateLocal, StateRemote, TopologyDatabase, UpdateType,
};
use crate::SDU;
use crate::{next_task_id, MessageIdGenerator};
use pnet::datalink::MacAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{interval, Duration};
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
        let al_mac_address = local_al_mac_address;
        let mac_address = interface_mac_address;

        // Define TLVs
        let al_mac_tlv = TLV {
            tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
            tlv_length: 6,
            tlv_value: Some(AlMacAddress { al_mac_address }.serialize()),
        };

        let mac_address_tlv = TLV {
            tlv_type: IEEE1905TLVType::MacAddress.to_u8(),
            tlv_length: 6,
            tlv_value: Some(MacAddress { mac_address }.serialize()),
        };

        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(al_mac_tlv.serialize());
        serialized_payload.extend(mac_address_tlv.serialize());
        serialized_payload.extend(end_of_message_tlv.serialize());

        // Construct CMDU
        let cmdu_topology_discovery = CMDU {
            message_version: MessageVersion::Version2013.to_u8(),
            reserved: 0,
            message_type: CMDUType::TopologyDiscovery.to_u16(),
            message_id,
            fragment: 0,
            flags: 0x80,
            payload: serialized_payload,
        };
        //TODO only size based

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
            let topology_db =
                TopologyDatabase::get_instance(local_al_mac_address, interface.clone()).await;
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

            // Define TLVs
            let al_mac_address = local_al_mac_address;

            let al_mac_tlv = TLV {
                tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
                tlv_length: 6,
                tlv_value: Some(al_mac_address.octets().to_vec()),
            };
            //Vendor Specific TLV (OUI 00:90:96, payload 00 01 00)
            let vendor_info = VendorSpecificInfo {
                oui: COMCAST_OUI,                        // Comcast OUI (per your request)
                vendor_data: COMCAST_QUERY_TAG.to_vec(), // Vendor payload
            };
            let vendor_value = vendor_info.serialize();
            let vendor_specific_tlv = TLV {
                tlv_type: IEEE1905TLVType::VendorSpecificInfo.to_u8(),
                tlv_length: vendor_value.len() as u16, // 3 (OUI) + payload length
                tlv_value: Some(vendor_value),
            };

            let end_of_message_tlv = TLV {
                tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
                tlv_length: 0,
                tlv_value: None,
            };

            let mut serialized_payload = vec![];
            serialized_payload.extend(al_mac_tlv.serialize());
            serialized_payload.extend(vendor_specific_tlv.serialize());
            serialized_payload.extend(end_of_message_tlv.serialize());

            // Construct CMDU
            let cmdu_topology_query = CMDU {
                message_version: MessageVersion::Version2013.to_u8(),
                reserved: 0,
                message_type: CMDUType::TopologyQuery.to_u16(),
                message_id,
                fragment: 0,
                flags: 0x80,
                payload: serialized_payload,
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
            let topology_db =
                TopologyDatabase::get_instance(local_al_mac_address, interface.clone()).await;
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

            // Construct DeviceInformation TLV
            let ieee1905_local_interfaces: Vec<LocalInterface> = {
                let interfaces = topology_db.local_interface_list.read().await;
                interfaces
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(|iface| LocalInterface {
                        mac_address: iface.mac,
                        media_type: iface.media_type,
                        special_info: iface.media_type_extra.clone(),
                    })
                    .collect()
            };

            // Construct DeviceBridgingCapability TLV
            let device_bridging_capability_tlv = {
                let mut tuples_by_bridge = HashMap::<u32, Vec<MacAddr>>::new();
                for interface in topology_db
                    .local_interface_list
                    .read()
                    .await
                    .iter()
                    .flatten()
                {
                    if let Some(bridging_tuple) = interface.bridging_tuple {
                        tuples_by_bridge
                            .entry(bridging_tuple)
                            .or_default()
                            .push(interface.mac);
                    }
                }

                let mut tuples = Vec::new();
                for tuple in tuples_by_bridge.into_values() {
                    if tuple.len() > 1 {
                        tuples.push(BridgingTuple {
                            bridging_mac_count: tuple.len() as u8,
                            bridging_mac_list: tuple,
                        });
                    }
                }

                if !tuples.is_empty() {
                    let value = DeviceBridgingCapability {
                        bridging_tuples_count: tuples.len() as u8,
                        bridging_tuples_list: tuples,
                    }
                    .serialize();

                    Some(TLV {
                        tlv_type: IEEE1905TLVType::DeviceBridgingCapability.to_u8(),
                        tlv_length: value.len() as u16,
                        tlv_value: Some(value),
                    })
                } else {
                    None
                }
            };

            // Construct AL MAC TLV

            let al_mac_address: MacAddr = local_al_mac_address;
            warn!("this is the al mac I'm using {}", remote_al_mac_address);
            let al_mac_tlv = TLV {
                tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
                tlv_length: 6,
                tlv_value: Some(al_mac_address.octets().to_vec()),
            };
            let vendor_info = VendorSpecificInfo {
                oui: COMCAST_OUI,                        // Comcast OUI (per your request)
                vendor_data: COMCAST_QUERY_TAG.to_vec(), // Vendor payload
            };
            let vendor_value = vendor_info.serialize();
            let vendor_specific_tlv = TLV {
                tlv_type: IEEE1905TLVType::VendorSpecificInfo.to_u8(),
                tlv_length: vendor_value.len() as u16, // 3 (OUI) + payload length
                tlv_value: Some(vendor_value),
            };
            //Vendor Specific TLV (OUI 00:90:96, payload 00 01 00)
            let device_information =
                DeviceInformation::new(local_al_mac_address, ieee1905_local_interfaces);
            let device_information_vec = device_information.serialize();
            let device_information_tlv = TLV {
                tlv_type: IEEE1905TLVType::DeviceInformation.to_u8(),
                tlv_length: device_information_vec.len() as u16,
                tlv_value: Some(device_information_vec),
            };

            //TODO biridging TUPLE
            /*
            let mut bridging_tuples_list: Vec<BridgingTuple> = Vec::new();
            if let Some(ieee1905_local_interfaces) = node.device_data.local_interface_list.as_ref() {
                for iface in ieee1905_local_interfaces {
                    if iface.bridging_tuple.is_some() { // Check existence without using the variable
                        if let Some(non_ieee_neighbors) = &iface.non_ieee1905_neighbors {
                            let bridging_tuple = BridgingTuple {
                                bridging_mac_count: non_ieee_neighbors.len() as u8,
                                bridging_mac_list: non_ieee_neighbors.clone(),
                            };
                            bridging_tuples_list.push(bridging_tuple);
                        }
                    }
                }
            }
            */
            let ieee_neighbors_list: Vec<IEEE1905Neighbor> = {
                let mut list = Vec::new();
                let nodes = topology_db.nodes.read().await;

                for (neighbor_mac, neighbor_node) in nodes.iter() {
                    if *neighbor_mac == local_al_mac_address {
                        continue; // Dont include your self as a neighbor

                        // set neighbor_flags based on metadata
                    }
                    let neighbor_flags = match neighbor_node.metadata.lldp_neighbor.is_some() {
                        true => 0b1000_0000,
                        false => 0b0000_0000,
                    };

                    list.push(IEEE1905Neighbor {
                        neighbor_al_mac: *neighbor_mac,
                        neighbor_flags,
                    });
                }

                list
            };

            let ieee_neighbors_tlv = if ieee_neighbors_list.is_empty() {
                TLV {
                    tlv_type: IEEE1905TLVType::Ieee1905NeighborDevices.to_u8(),
                    tlv_length: 0,
                    tlv_value: None,
                }
            } else {
                let ieee_neighbors = Ieee1905NeighborDevice {
                    local_mac_address: interface_mac_address,
                    neighborhood_list: ieee_neighbors_list,
                };
                let serialized = ieee_neighbors.serialize();
                TLV {
                    tlv_type: IEEE1905TLVType::Ieee1905NeighborDevices.to_u8(),
                    tlv_length: serialized.len() as u16,
                    tlv_value: Some(serialized),
                }
            };

            // End of Message TLV
            let end_of_message_tlv = TLV {
                tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
                tlv_length: 0,
                tlv_value: None,
            };

            let mut serialized_payload = vec![];
            serialized_payload.extend(al_mac_tlv.serialize());
            serialized_payload.extend(vendor_specific_tlv.serialize());
            serialized_payload.extend(device_information_tlv.serialize());
            serialized_payload.extend(ieee_neighbors_tlv.serialize());
            if let Some(device_bridging_capability_tlv) = device_bridging_capability_tlv {
                serialized_payload.extend(device_bridging_capability_tlv.serialize());
            }
            serialized_payload.extend(end_of_message_tlv.serialize());

            // Construct the CMDU
            let cmdu_topology_response = CMDU {
                message_version: MessageVersion::Version2013.to_u8(),
                reserved: 0,
                message_type: CMDUType::TopologyResponse.to_u16(),
                message_id,
                fragment: 0,
                flags: 0x80, // Not fragmented
                payload: serialized_payload,
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

                    info!("Topology Database updated: AL_MAC={al_mac_address} set to ResponseSent");
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

            let topology_db =
                TopologyDatabase::get_instance(local_al_mac_address, interface.clone()).await;

            // Define the AL MAC TLV
            let al_mac_address: MacAddr = local_al_mac_address;
            let al_mac_tlv = TLV {
                tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
                tlv_length: 6,
                tlv_value: Some(al_mac_address.octets().to_vec()),
            };

            // Define the End of Message TLV
            let end_of_message_tlv = TLV {
                tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
                tlv_length: 0,
                tlv_value: None,
            };

            //Vendor Specific TLV (OUI 00:90:96, payload 00 01 00)
            let vendor_info = VendorSpecificInfo {
                oui: COMCAST_OUI,                        // Comcast OUI (per your request)
                vendor_data: COMCAST_QUERY_TAG.to_vec(), // Vendor payload
            };
            let vendor_value = vendor_info.serialize();
            let vendor_specific_tlv = TLV {
                tlv_type: IEEE1905TLVType::VendorSpecificInfo.to_u8(),
                tlv_length: vendor_value.len() as u16, // 3 (OUI) + payload length
                tlv_value: Some(vendor_value),
            };

            let mut serialized_payload = vec![];
            serialized_payload.extend(al_mac_tlv.serialize());
            serialized_payload.extend(vendor_specific_tlv.serialize());
            serialized_payload.extend(end_of_message_tlv.serialize());

            // Construct the Topology Notification CMDU
            let cmdu_topology_notification = CMDU {
                message_version: MessageVersion::Version2013.to_u8(),
                reserved: 0,
                message_type: CMDUType::TopologyNotification.to_u16(),
                message_id,
                fragment: 0,
                flags: 0x80, // Not fragmented
                payload: serialized_payload,
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
    let topology_db = TopologyDatabase::get_instance(local_al_mac_address, interface.clone()).await;
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

            let metric = LinkMetricRx {
                source_al_mac: local_al_mac_address,
                neighbour_al_mac: neighbor.device_data.al_mac,
                interface_pairs: vec![pair],
            };

            let metric_buf = metric.serialize();
            tlvs.push(TLV {
                tlv_type: IEEE1905TLVType::LinkMetricRx.to_u8(),
                tlv_length: metric_buf.len() as u16,
                tlv_value: Some(metric_buf),
            })
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

            let metric = LinkMetricTx {
                source_al_mac: local_al_mac_address,
                neighbour_al_mac: neighbor.device_data.al_mac,
                interface_pairs: vec![pair],
            };

            let metric_buf = metric.serialize();
            tlvs.push(TLV {
                tlv_type: IEEE1905TLVType::LinkMetricTx.to_u8(),
                tlv_length: metric_buf.len() as u16,
                tlv_value: Some(metric_buf),
            })
        }
    }

    // End of message TLV
    tlvs.push(TLV {
        tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
        tlv_length: 0,
        tlv_value: None,
    });

    // Construct CMDU
    let cmdu = CMDU {
        message_version: MessageVersion::Version2013.to_u8(),
        reserved: 0,
        message_type: CMDUType::LinkMetricResponse.to_u16(),
        message_id,
        fragment: 0,
        flags: 0x80,
        payload: tlvs.iter().map(TLV::serialize).flatten().collect(),
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
        trace!(?sdu, "Parsing CMDU from SDU payload");
        let destination_al_mac = sdu.destination_al_mac_address;
        let fragmentation;
        match CMDU::parse(&sdu.payload) {
            Ok((_, cmdu)) => {
                let destination_mac = if sdu.destination_al_mac_address == IEEE1905_CONTROL_ADDRESS
                {
                    trace!("Parsing CMDU from SDU payload destination mac address is IEEE1905_CONTROL_ADDRESS");
                    fragmentation = CMDUFragmentation::default();
                    IEEE1905_CONTROL_ADDRESS
                } else {
                    trace!(
                        "Acquiry topology database for source al mac address {}",
                        sdu.source_al_mac_address
                    );

                    let topology_db = TopologyDatabase::get_instance(
                        sdu.source_al_mac_address,
                        interface.clone(),
                    )
                        .await;

                    trace!("Searching for destination {destination_al_mac} in topology database");

                    let Some(node) = topology_db.get_device(sdu.destination_al_mac_address).await else {
                        return warn!("No destination_mac found for AL-MAC {destination_al_mac}");
                    };
                    if node.metadata.node_state_local != StateLocal::ConvergedLocal {
                        return warn!("node has not locally converged, AL-MAC={destination_al_mac}");
                    }
                    if node.metadata.node_state_remote != StateRemote::ConvergedRemote {
                        return warn!("node has not remotely converged, AL-MAC={destination_al_mac}");
                    }

                    fragmentation = node.device_data.supported_fragmentation;
                    node.device_data.destination_frame_mac
                };
                let source_mac = match get_mac_address_by_interface(&interface) {
                    Some(mac) => mac,
                    None => {
                        return warn!("Interface {} not found or has no MAC address", interface);
                    }
                };

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
