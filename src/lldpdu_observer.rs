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
use nom::Err as NomErr;
use pnet::datalink::MacAddr;
use tracing::{debug, error, info, warn};

// Internal modules
use crate::ethernet_subject_reception::EthernetFrameObserver;
use crate::lldpdu::{LLDPDU, LLDPTLVType, ChassisId, PortId};
use crate::topology_manager::{TopologyDatabase, UpdateType};

#[derive(Clone)]
pub struct LLDPObserver {
    pub local_chassis_id: MacAddr, // Local AL MAC address
    pub interface_name: String,
}

impl LLDPObserver {
    /// Creates a new `LLDPObserver` with a given chassis ID.
    pub fn new(local_chassis_id: MacAddr, interface_name: String) -> Self {
        Self { local_chassis_id, interface_name }
    }
}

#[async_trait]
impl EthernetFrameObserver for LLDPObserver {
    async fn on_frame(&self, interface_mac: MacAddr, frame: &[u8], source_mac: MacAddr, destination_mac: MacAddr) {
        debug!(
            interface_mac = ?interface_mac,
            source_mac = ?source_mac,
            destination_mac = ?destination_mac,
            frame_length = frame.len(),
            "Received LLDP frame"
        );

        match LLDPDU::parse(frame) {
            Ok((_, lldpdu)) => {
                info!(
                    interface_mac = ?interface_mac,
                    "Received LLDPDU from {} to {}",
                    source_mac, destination_mac
                );

                let mut chassis_id: Option<MacAddr> = None;
                let mut port_id: Option<PortId> = None;


                // Iterate through TLVs in the LLDPDU payload
                for (index, tlv) in lldpdu.payload.iter().enumerate() {
                    debug!(
                        interface_mac = ?interface_mac,
                        "TLV {}: Type = 0x{:02X}, Length = {}, Value: {:?}",
                        index + 1,
                        tlv.tlv_type,
                        tlv.tlv_length,
                        tlv.tlv_value
                    );

                    match LLDPTLVType::from_u8(tlv.tlv_type) {
                        LLDPTLVType::ChassisId => {
                            if let Some(value) = &tlv.tlv_value {
                                match ChassisId::parse(value, tlv.tlv_length) {
                                    Ok((_, parsed_chassis_id)) => {
                                        chassis_id = Some(parsed_chassis_id.chassis_id);
                                        info!(
                                            interface_mac = ?interface_mac,
                                            "Parsed Chassis ID: {:?}",
                                            parsed_chassis_id.chassis_id
                                        );
                                    }
                                    Err(NomErr::Failure(e)) => {
                                        warn!(
                                            interface_mac = ?interface_mac,
                                            "Failed to parse Chassis ID TLV: {:?}", e
                                        );
                                    }
                                    Err(_) => {
                                        warn!(
                                            interface_mac = ?interface_mac,
                                            "Unexpected error while parsing Chassis ID TLV"
                                        );
                                    }
                                }
                            }
                        }
                        LLDPTLVType::PortId => {
                            if let Some(value) = &tlv.tlv_value {
                                match PortId::parse(value, tlv.tlv_length) {
                                    Ok((_, parsed_port_id)) => {
                                        info!(
                                            interface_mac = ?interface_mac,
                                            "Parsed Port ID: {:?}",
                                            parsed_port_id.port_id,
                                        );
                                        port_id = Some(parsed_port_id);
                                    }
                                    Err(NomErr::Failure(e)) => {
                                        warn!(
                                            interface_mac = ?interface_mac,
                                            "Failed to parse Port ID TLV: {:?}", e
                                        );
                                    }
                                    Err(_) => {
                                        warn!(
                                            interface_mac = ?interface_mac,
                                            "Unexpected error while parsing Port ID TLV"
                                        );
                                    }
                                }
                            }
                        }
                        _ => {
                            debug!(
                                interface_mac = ?interface_mac,
                                "Ignoring TLV Type: 0x{:02X}", tlv.tlv_type
                            );
                        }
                    }
                }

                // If a valid chassis_id and port_id were found, update the topology database
                let Some(neighbor_chassis_id) = chassis_id else {
                    return;
                };
                let Some(port_id) = port_id else {
                    return;
                };

                // Check if the neighbor chassis ID is different from the local chassis ID to prevent loops
                if neighbor_chassis_id == self.local_chassis_id {
                    // Log when a loop is detected
                    return tracing::trace!(
                        "Loop detected: neighbor_chassis_id ({:?}) is equal to local_chassis_id ({:?})",
                        neighbor_chassis_id, self.local_chassis_id
                    );
                }

                // Check if the neighbor chassis ID is different from the local chassis ID to prevent loops
                debug!(
                    interface_mac = ?interface_mac,
                    "Updating topology database for chassis MAC: {:?}",
                    neighbor_chassis_id
                );

                let topology_db = TopologyDatabase::get_instance(self.local_chassis_id, self.interface_name.clone()).await;

                // If a valid port_id is found, update the topology
                if let Some(node) = topology_db.get_device(neighbor_chassis_id).await {
                    tracing::info!("Device found: {:?}", node);

                    topology_db.update_ieee1905_topology(
                        node.device_data.clone(),
                        UpdateType::LldpUpdate,
                        None,
                        Some(port_id),
                    ).await;
                } else {
                    tracing::warn!("Device with AL-MAC {} not found!", neighbor_chassis_id);
                }
            }
            Err(e) => {
                error!(
                    interface_mac = ?interface_mac,
                    "Failed to parse LLDPDU: {:?}", e
                );
            }
        }
    }

    fn get_ethertype(&self) -> u16 {
        0x88CC // EtherType for LLDP
    }
}
