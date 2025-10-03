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

use pnet::datalink::MacAddr;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, trace, warn};
use std::sync::Arc;
use crate::cmdu::TLV;
use crate::cmdu_codec::*;
use crate::ethernet_subject_transmission::EthernetSender;
use crate::interface_manager::get_mac_address_by_interface;
use crate::topology_manager::{TopologyDatabase, UpdateType};
use crate::MessageIdGenerator;
use crate::SDU;

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
            serialized_payload.extend(al_mac_tlv.serialize() );
            serialized_payload.extend( mac_address_tlv.serialize() );
            serialized_payload.extend( end_of_message_tlv.serialize() );

        // Construct CMDU
        let cmdu_topology_discovery = CMDU {
            message_version: 1,
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
            .send_frame(
                destination_mac,
                interface_mac_address,
                ethertype,
                &serialized_cmdu,
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
    let destination_mac = device_data.destination_mac.unwrap_or_else(|| {
        debug!(
            "Node AL_MAC={} has no destination MAC address, using default IEEE 1905 multicast",
            remote_al_mac_address
        );
        MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x13) // Default IEEE 1905 multicast
    });

    // Define TLVs
    let al_mac_address = local_al_mac_address;

    let al_mac_tlv = TLV {
        tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
        tlv_length: 6,
        tlv_value: Some(al_mac_address.octets().to_vec()),
    };

    let end_of_message_tlv = TLV {
        tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
        tlv_length: 0,
        tlv_value: None,
    };
    let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(al_mac_tlv.serialize() );
        serialized_payload.extend( end_of_message_tlv.serialize() );
    // Construct CMDU
    let cmdu_topology_query = CMDU {
        message_version: 1,
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
        .send_frame(destination_mac, source_mac, ethertype, &serialized_cmdu)
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
                )
                .await;
            debug!(
                "Updated topology database: AL_MAC={} set to QUERY_SENT",
                remote_al_mac_address
            );
        }
    }
}

pub async fn cmdu_topology_response_transmission(
    interface: String,
    sender: Arc<EthernetSender>,
    local_al_mac_address: MacAddr,
    remote_al_mac_address: MacAddr,
    interface_mac_address: MacAddr,
) {
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

    let message_id: u16 = node.metadata.message_id.unwrap_or(0);

    // Retrieve Forwarding MAC Address from Database
    let forwarding_mac_address = match node.device_data.destination_mac {
        Some(mac) => mac,
        None => {
            warn!(
                "Node AL_MAC={} has no forwarding MAC address, using default IEEE 1905 multicast",
                remote_al_mac_address
            );
            MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x13) // we put all zeros
        }
    };

    // Construct DeviceInformation TLV
    let ieee1905_local_interfaces: Vec<LocalInterface> = topology_db
        .local_interface_list
        .read()
        .await
        .as_ref()
        .map(|interfaces| {
            interfaces
                .iter()
                .map(|iface| {
                    LocalInterface {
                        mac_address: iface.mac,
                        media_type: iface.media_type,
                        special_info: vec![], // No additional special info
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // Construct AL MAC TLV

    let al_mac_address: MacAddr = local_al_mac_address;
    warn!("this is the al mac I'm using {}", remote_al_mac_address);
    let al_mac_tlv = TLV {
        tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
        tlv_length: 6,
        tlv_value: Some(al_mac_address.octets().to_vec()),
    };

    let device_information =
        DeviceInformation::new(local_al_mac_address, ieee1905_local_interfaces);
    let device_information_tlv = TLV {
        tlv_type: IEEE1905TLVType::DeviceInformation.to_u8(),
        tlv_length: device_information.serialize().len() as u16,
        tlv_value: Some(device_information.serialize()),
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

    let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(al_mac_tlv.serialize() );
        serialized_payload.extend( device_information_tlv.serialize() );
        serialized_payload.extend( ieee_neighbors_tlv.serialize() );
        serialized_payload.extend( end_of_message_tlv.serialize() );

    // Construct the CMDU
    let cmdu_topology_response = CMDU {
        message_version: 1,
        reserved: 0,
        message_type: CMDUType::TopologyResponse.to_u16(),
        message_id,
        fragment: 0,
        flags: 0x80, // Not fragmented
        payload: serialized_payload,
    };

    // Serialize CMDU
    let serialized_cmdu = cmdu_topology_response.serialize();
    debug!(
        message_id = message_id,
        ?serialized_cmdu,
        "Serialized CMDU for Topology Response"
    );

    // Set destination MAC
    let destination_mac = forwarding_mac_address;
    let source_mac = interface_mac_address;
    let ethertype = 0x893A; // IEEE 1905 EtherType

    // Send the CMDU via EthernetSender
    match sender
        .send_frame(destination_mac, source_mac, ethertype, &serialized_cmdu)
        .await
    {
        Ok(()) => {
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
                    Some(message_id),
                    None,
                )
                .await;

            info!(
                "Topology Database updated: AL_MAC={} set to ResponseSent",
                al_mac_address
            );
        }
        Err(e) => {
            error!(
                message_id = message_id,
                "Failed to send CMDU Topology Response: {}", e
            );
        }
    }
}

pub async fn cmdu_topology_notification_transmission(
    interface: String,
    sender: Arc<EthernetSender>,
    message_id_generator: Arc<MessageIdGenerator>,
    local_al_mac_address: MacAddr,
    forwarding_interface_mac: MacAddr
) {
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


    let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(al_mac_tlv.serialize() );
        serialized_payload.extend( end_of_message_tlv.serialize() );

    // Construct the Topology Notification CMDU
    let cmdu_topology_notification = CMDU {
        message_version: 1,
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
        .send_frame(destination_mac, source_mac, ethertype, &serialized_cmdu)
        .await
    {
        Ok(()) => info!(
            interface = %interface,
            message_id = message_id,
            "CMDU Topology Notification sent successfully"
        ),
        Err(e) => error!(
            message_id = message_id,
            "Failed to send CMDU Topology Notification: {}", e
        ),
    }
}

pub async fn cmdu_from_sdu_transmission(
    interface: String,
    sender: Arc<EthernetSender>,
    sdu: SDU,
) {
    trace!(?sdu, "Parsing CMDU from SDU payload");
    match CMDU::parse(&sdu.payload) {
        Ok((_, cmdu)) => {
            let destination_mac = if sdu.destination_al_mac_address == IEEE1905_CONTROL_ADDRESS
            {
                trace!("Parsing CMDU from SDU payload destination mac address is IEEE1905_CONTROL_ADDRESS");
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
                trace!(
                    "Sarching for destination {} in topology database",
                    sdu.destination_al_mac_address
                );
                let Some(node) = topology_db.get_device(sdu.destination_al_mac_address).await
                else {
                    tracing::warn!(
                        "No destination_mac found for AL-MAC {}",
                        sdu.source_al_mac_address
                    );
                    return;
                };
                match node.device_data.destination_mac {
                    Some(mac) => mac,
                    None => {
                        error!(
                            "Destination MAC address is missing for AL-MAC={}",
                            sdu.destination_al_mac_address
                        );
                        return;
                    }
                }
            };
            let source_mac = match get_mac_address_by_interface(&interface) {
                Some(mac) => {
                    mac
                }
                None => {
                    tracing::warn!("Interface {} not found or has no MAC address", interface);
                    return;
                }
            };
            let ethertype = 0x893A;

            let fragments = if cmdu.total_size() > 1500 {
                tracing::trace!("CMDU will be fragmented. CMDU total size {} max size 1500",cmdu.total_size());
                cmdu.fragment(1500)
            } else {
                vec![cmdu]
            };
            for fragment in fragments {
                let serialized = fragment.serialize();
                let fragment_id = fragment.fragment;
                tracing::trace!("Sending CMDU fragment <{serialized:?}> dstMacAddr {destination_mac:?}, src_mac {source_mac:?}, ethertype {ethertype:?}");
                match sender
                    .send_frame(destination_mac, source_mac, ethertype, &serialized)
                    .await
                {
                    Ok(()) => {
                        info!(fragment = fragment_id, "CMDU fragment sent")
                    }
                    Err(e) => {
                        error!(
                            fragment = fragment_id,
                            "Failed to send CMDU fragment: {}", e
                        )
                    }
                }
            }
        },
        Err(_) => {
            error!("Failed to parse CMDU from SDU payload!");
        }
    }
}
