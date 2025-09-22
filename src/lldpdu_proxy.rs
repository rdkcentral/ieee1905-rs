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
use pnet::datalink::MacAddr;
use crate::lldpdu::{LLDPDU, LLDPTLVType, TLV, ChassisId, PortId, TimeToLiveTLV};
use crate::ethernet_subject_transmission::EthernetSender;
use tokio::task;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, error}; // Import tracing

/// Launches the discovery process for L2 devices using LLDP.
pub fn lldp_discovery(
    sender: EthernetSender,
    chassis_id: MacAddr,
    port_id: MacAddr,
    port_name: String,
) -> LldpDiscoveryTask {
    let task_handle = task::spawn(async move {
        sleep(Duration::from_secs(10)).await;
        loop {
            info!("Starting LLDP discovery process on interface: {port_name}");

            let chassis_id_struct = ChassisId {
                chassis_id_type: 4, // 4 = MAC Address type in LLDP
                chassis_id,
            };

            let port_id_struct = PortId {
                port_id_subtype: 3, // 3 = MAC Address subtype in LLDP
                port_id,
            };


            let chassis_id_tlv = TLV {
                tlv_type: LLDPTLVType::ChassisId.to_u8(),
                tlv_length: chassis_id_struct.serialize().len() as u16,
                tlv_value: Some(chassis_id_struct.serialize()),
            };

            let port_id_tlv = TLV {
                tlv_type: LLDPTLVType::PortId.to_u8(),
                tlv_length: port_id_struct.serialize().len() as u16,
                tlv_value: Some(port_id_struct.serialize()),
            };
            let ttl_tlv = TimeToLiveTLV { ttl: 120 };
            let time_to_live_tlv = TLV {
                tlv_type: LLDPTLVType::TimeToLive.to_u8(),
                tlv_length: ttl_tlv.serialize().len() as u16,
                tlv_value: Some(ttl_tlv.serialize()),
            };

            let end_of_lldpdu_tlv = TLV {
                tlv_type: LLDPTLVType::EndOfLldpdu.to_u8(),
                tlv_length: 0,
                tlv_value: None,
            };

            debug!(
                "Generated TLVs: Chassis ID: {:?}, Port ID: {:?}, TTL: {}",
                chassis_id, port_id, ttl_tlv.ttl
            );

            let lldpdu = LLDPDU {
                payload: vec![
                    chassis_id_tlv,
                    port_id_tlv,
                    time_to_live_tlv,
                    end_of_lldpdu_tlv,
                ],
            };

            // Serialize the LLDPDU
            let serialized_lldpdu = lldpdu.serialize();
            debug!("Serialized LLDPDU ({} bytes): {:?}", serialized_lldpdu.len(), serialized_lldpdu);

            // Transmit the LLDPDU
            let destination_mac = MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E); // LLDP Multicast
            let source_mac = port_id; // Use port_id as source MAC
            let ethertype = 0x88CC; // EtherType for LLDP

            match sender.send_frame(destination_mac, source_mac, ethertype, &serialized_lldpdu).await {
                Ok(()) => info!("LLDPDU sent successfully through {port_name}"),
                Err(e) => error!("Failed to send LLDPDU: {}", e),
            }

            // Async wait before sending the next LLDPDU
            sleep(Duration::from_secs(10)).await;
        }
    });

    LldpDiscoveryTask {
        handle: task_handle,
    }
}

pub struct LldpDiscoveryTask {
    handle: JoinHandle<()>,
}

impl Drop for LldpDiscoveryTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
