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
use anyhow::bail;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};

use crate::al_sap::service_access_point_data_indication;
use crate::cmdu::{CMDUType, CMDU};
use crate::cmdu_codec::*;
use crate::cmdu_proxy::*;
use crate::cmdu_reassembler::CmduReassembler;
use crate::ethernet_subject_transmission::EthernetSender;
use crate::sdu_codec::SDU;
use crate::tlv_cmdu_codec::TLV;
use crate::topology_manager::*;
use crate::MessageIdGenerator;
use pnet::datalink::MacAddr;

///the handler has to take care of the reassembly
pub struct CMDUHandler {
    sender: Arc<EthernetSender>,
    message_id_generator: Arc<MessageIdGenerator>,
    local_al_mac: MacAddr,
    pub interface_name: String,
    pub reassembler: Arc<CmduReassembler>,
}

impl CMDUHandler {
    const MAX_CMDU_SIZE: usize = 1500;

    pub async fn new(
        sender: Arc<EthernetSender>,
        message_id_generator: Arc<MessageIdGenerator>,
        local_al_mac: MacAddr,
        interface_name: String,
    ) -> Self {
        Self {
            sender,
            message_id_generator,
            local_al_mac,
            interface_name,
            reassembler: Arc::new(CmduReassembler::new()),
        }
    }

    pub async fn handle_cmdu(
        &self,
        cmdu: &CMDU,
        source_mac: MacAddr,
        destination_mac: MacAddr,
    ) -> anyhow::Result<()> {
        tracing::trace!("Handling CMDU <{cmdu:?}> source mac: {source_mac}, destination_mac {destination_mac:?}");

        if cmdu.total_size() > Self::MAX_CMDU_SIZE {
            bail!(
                "CMDU should have maximum {} bytes but is {} bytes long",
                Self::MAX_CMDU_SIZE,
                cmdu.total_size()
            );
        }

        let cmdu_to_process = if cmdu.is_fragmented() {
            let fragment_clone = cmdu.clone();

            match self
                .reassembler
                .push_fragment(source_mac, fragment_clone)
                .await
            {
                Some(Ok(full_cmdu)) => {
                    debug!(
                        "CMDU completely reassembled MessageID {:?} fragment {:?}",
                        cmdu.message_id, cmdu.fragment
                    );
                    full_cmdu
                }
                Some(Err(e)) => {
                    bail!("Error reassembling CMDU: {e:?}");
                }
                None => {
                    trace!(
                        "Fragment stored. Waiting for more... MessageID {:?} fragment {:?}",
                        cmdu.message_id,
                        cmdu.fragment
                    );
                    return Ok(());
                }
            }
        } else {
            cmdu.clone()
        };

        if !self.filter_incoming_cmdu(&cmdu).await {
            return Ok(());
        }

        tracing::trace!("Dispatching CMDU {cmdu_to_process:?} source mac {source_mac:?} destination_mac {destination_mac:?}");
        self.dispatch_cmdu(cmdu_to_process, source_mac, destination_mac).await;
        Ok(())
    }

    /// Handles a parsed CMDU, logs details, and extracts TLVs.
    async fn dispatch_cmdu(&self, cmdu: CMDU, source_mac: MacAddr, destination_mac: MacAddr) {
        tracing::trace!("Dispatch CMDU {cmdu:?}");
        let message_id = cmdu.message_id;

        let tlvs = match cmdu.get_tlvs() {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to parse TLVs (msg_id={}): {:?}", message_id, e);
                return;
            }
        };

        match CMDUType::from_u16(cmdu.message_type) {
            CMDUType::TopologyDiscovery => {
                self.handle_topology_discovery(&tlvs, message_id).await;
            }
            CMDUType::TopologyNotification => {
                let handled = self.handle_topology_notification(&tlvs, message_id).await;
                if !handled {
                    if let Err(e) = self
                        .handle_sdu_from_cmdu_reception(
                            &tlvs,
                            message_id,
                            cmdu.message_type,
                            source_mac,
                            destination_mac,
                        )
                        .await
                    {
                        error!("Error forwarding SDU from TopologyNotification interoperability (msg_id={message_id}): {e:?}");
                    }
                }
            }
            CMDUType::TopologyQuery => {
                let handled = self
                    .handle_topology_query(&tlvs, message_id, source_mac)
                    .await;
                if !handled {
                    if let Err(e) = self
                        .handle_sdu_from_cmdu_reception(
                            &tlvs,
                            message_id,
                            cmdu.message_type,
                            source_mac,
                            destination_mac,
                        )
                        .await
                    {
                        error!("Error forwarding SDU from TopologyQuery interoperability (msg_id={message_id}): {e:?}");
                    }
                }
            }
            CMDUType::TopologyResponse => {
                let handled = self.handle_topology_response(&tlvs, message_id).await;
                if !handled {
                    if let Err(e) = self
                        .handle_sdu_from_cmdu_reception(
                            &tlvs,
                            message_id,
                            cmdu.message_type,
                            source_mac,
                            destination_mac,
                        )
                        .await
                    {
                        error!("Error forwarding SDU from TopologyResponse interoperability (msg_id={message_id}): {e:?}");
                    }
                }
            }
            CMDUType::ApAutoConfigSearch => {
                debug!("Handling ApAutoConfigSearch CMDU");
                let allowed = self.handle_ap_auto_config_search(&tlvs, message_id).await;
                if allowed {
                    if let Err(e) = self
                        .handle_sdu_from_cmdu_reception(
                            &tlvs,
                            message_id,
                            cmdu.message_type,
                            source_mac,
                            destination_mac,
                        )
                        .await
                    {
                        error!("Error forwarding SDU from ApAutoConfigSearch (msg_id={message_id}): {e:?}");
                    }
                }
            }
            CMDUType::ApAutoConfigResponse => {
                debug!("Handling ApAutoConfigResponse CMDU");
                let allowed = self.handle_ap_auto_config_response(&tlvs, message_id, source_mac).await;
                if allowed {
                    if let Err(e) = self
                        .handle_sdu_from_cmdu_reception(
                            &tlvs,
                            message_id,
                            cmdu.message_type,
                            source_mac,
                            destination_mac,
                        )
                        .await
                    {
                        error!("Error forwarding SDU from ApAutoConfigResponse (msg_id={message_id}): {e:?}");
                    }
                }
            }
            CMDUType::LinkMetricQuery => {
                tracing::info!("Handling Link Metric Query CMDU");
            }
            CMDUType::LinkMetricResponse => {
                tracing::info!("Handling Link Metric Response CMDU");
            }
            CMDUType::Unknown(_) => {
                if let Err(e) = self
                    .handle_sdu_from_cmdu_reception(
                        &tlvs,
                        message_id,
                        cmdu.message_type,
                        source_mac,
                        destination_mac,
                    )
                    .await
                {
                    tracing::error!(
                        "Error forwarding SDU from CMDU (msg_id={}): {:?}",
                        message_id,
                        e
                    );
                }
            }
        }
    }

    /// Handles and logs TLVs from the CMDU payload for Topology Discovery.
    async fn handle_topology_discovery(&self, tlvs: &[TLV], message_id: u16) {
        debug!(
            "Handling Topology Discovery CMDU with Message ID: {}, from interface {}",
            message_id, self.interface_name
        );

        let mut remote_al_mac: Option<MacAddr> = None;
        let mut remote_interface_mac: Option<MacAddr> = None;
        let mut end_of_message_found = false;

        for (index, tlv) in tlvs.iter().enumerate() {
            trace!(
                index,
                tlv_type = ?IEEE1905TLVType::from_u8(tlv.tlv_type),
                length = tlv.tlv_length,
                "Processing TLV"
            );

            match IEEE1905TLVType::from_u8(tlv.tlv_type) {
                IEEE1905TLVType::AlMacAddress => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed)) = AlMacAddress::parse(value) {
                            remote_al_mac = Some(parsed.al_mac_address);
                        }
                    }
                }
                IEEE1905TLVType::MacAddress => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed)) = MacAddress::parse(value) {
                            remote_interface_mac = Some(parsed.mac_address);
                        }
                    }
                }
                IEEE1905TLVType::EndOfMessage => {
                    end_of_message_found = true;
                    trace!("End of CMDU Message found");
                }
                _ => warn!("Unknown TLV Type, Raw Data: {:?}", tlv.tlv_value),
            }
        }

        if !end_of_message_found {
            error!("Topology Discovery CMDU is missing the required End of Message TLV. Ignoring CMDU.");
            return;
        }

        if let (Some(remote_al_mac_address), Some(neighbor_interface_mac_address)) =
            (remote_al_mac, remote_interface_mac)
        {
            let topology_db =
                TopologyDatabase::get_instance(self.local_al_mac, self.interface_name.clone())
                    .await;

            let device_data = Ieee1905DeviceData {
                al_mac: remote_al_mac_address,
                destination_mac: Some(neighbor_interface_mac_address),
                local_interface_list: None,
                registry_role: None,
            };

            let event = topology_db
                .update_ieee1905_topology(
                    device_data,
                    UpdateType::DiscoveryReceived,
                    Some(message_id),
                    None,
                    None,
                )
                .await;

            info!(
                "Topology Discovery Processed: AL_MAC={} INTERFACE_MAC={}",
                remote_al_mac_address, neighbor_interface_mac_address
            );

            // Now react to the event
            match event {
                TransmissionEvent::SendTopologyQuery(destination_mac) => {
                    let forwarding_interface_mac = topology_db.get_forwarding_interface_mac().await;

                    cmdu_topology_query_transmission(
                        self.interface_name.clone(),
                        Arc::clone(&self.sender),
                        Arc::clone(&self.message_id_generator),
                        self.local_al_mac,
                        destination_mac,
                        forwarding_interface_mac,
                    )
                    .await;
                }
                TransmissionEvent::None => {
                    debug!(
                        remote = %remote_al_mac_address,
                        "No transmission needed after topology discovery update"
                    );
                }
                _ => {} // Future proof if more event types appear
            }
        } else {
            if remote_al_mac.is_none() {
                warn!("Topology Discovery failed: Missing AL MAC Address TLV");
            }
            if remote_interface_mac.is_none() {
                warn!("Topology Discovery failed: Missing Neighbor Interface MAC TLV");
            }
        }
    }

    /// Handles and logs TLVs for Topology Query.
    async fn handle_topology_query(
        &self,
        tlvs: &[TLV],
        message_id: u16,
        source_mac: MacAddr,
    ) -> bool {
        tracing::debug!(
            "Handling Topology Query CMDU on interface {}",
            self.interface_name
        );

        let mut remote_al_mac: Option<MacAddr> = None;
        let mut end_of_message_found = false;
        let mut device_vendor = Ieee1905DeviceVendor::Unknown;

        for (index, tlv) in tlvs.iter().enumerate() {
            let tlv_type = IEEE1905TLVType::from_u8(tlv.tlv_type);
            tracing::trace!(
                index,
                tlv_type = ?tlv_type,
                length = tlv.tlv_length,
                "Processing TLV"
            );

            match tlv_type {
                IEEE1905TLVType::AlMacAddress => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed)) = AlMacAddress::parse(value) {
                            remote_al_mac = Some(parsed.al_mac_address);
                            tracing::debug!("Extracted AL MAC Address: {}", parsed.al_mac_address);
                        }
                    }
                }
                IEEE1905TLVType::VendorSpecificInfo => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed_vs)) = VendorSpecificInfo::parse(value, tlv.tlv_length)
                        {
                            tracing::trace!(
                                "VendorSpecific TLV found: OUI={:02x}:{:02x}:{:02x}, len={}",
                                parsed_vs.oui[0],
                                parsed_vs.oui[1],
                                parsed_vs.oui[2],
                                parsed_vs.vendor_data.len()
                            );

                            if parsed_vs.oui == COMCAST_OUI
                                && parsed_vs.vendor_data.starts_with(COMCAST_QUERY_TAG)
                            {
                                device_vendor = Ieee1905DeviceVendor::Rdk;
                                tracing::debug!(
                                    "Matched Comcast VendorSpecific TLV (00:90:96 / 00 01 00)."
                                );
                            }
                        }
                    }
                }
                IEEE1905TLVType::EndOfMessage => {
                    end_of_message_found = true;
                    tracing::trace!("End of CMDU Message found");
                }
                _ => tracing::trace!("Ignoring TLV type {:?}", tlv_type),
            }
        }

        if !end_of_message_found {
            tracing::error!("Topology Query CMDU missing EndOfMessage TLV → discarding message.");
            return true;
        }

        info!("Topology Query received from REMOTE_PORT_MAC={source_mac}");

        let topology_db = TopologyDatabase::get_instance(
            self.local_al_mac,
            self.interface_name.clone(),
        ).await;

        let device_data = if let Some(remote_al_mac) = remote_al_mac {
            Ieee1905DeviceData {
                al_mac: remote_al_mac,
                destination_mac: Some(source_mac),
                local_interface_list: None,
                registry_role: None,
            }
        } else {
            let Some(mut node) = topology_db.find_device_by_port(source_mac).await else {
                warn!("Topology Query node not found, REMOTE_PORT_MAC={source_mac}");
                return false;
            };
            node.device_data.destination_mac = Some(source_mac);
            node.device_data
        };

        let remote_al_mac = device_data.al_mac;
        let event = topology_db
            .update_ieee1905_topology(
                device_data,
                UpdateType::QueryReceived,
                Some(message_id),
                None,
                Some(device_vendor),
            )
            .await;

        debug!("Topology Database updated: AL_MAC={remote_al_mac} set to QueryReceived");

        match event {
            TransmissionEvent::SendTopologyResponse(destination_mac) => {
                debug!(
                    remote = %remote_al_mac,
                    local = %self.local_al_mac,
                    "Preparing to send Topology Response"
                );

                let forwarding_interface_mac = topology_db.get_forwarding_interface_mac().await;

                cmdu_topology_response_transmission(
                    self.interface_name.clone(),
                    self.sender.clone(),
                    self.local_al_mac,
                    destination_mac,
                    forwarding_interface_mac,
                )
                .await;
            }
            TransmissionEvent::None => {
                debug!(
                    remote = %remote_al_mac,
                    "No transmission needed after topology query update"
                );
            }
            _ => {}
        };

        true
    }

    /// Handles and logs TLVs for Topology Response.
    async fn handle_topology_response(&self, tlvs: &[TLV], message_id: u16) -> bool {
        tracing::debug!(
            "Handling Topology Response CMDU with Message ID: {} from interface {}",
            message_id,
            self.interface_name
        );

        let mut remote_al_mac: Option<MacAddr> = None;
        let mut interfaces: Vec<Ieee1905InterfaceData> = Vec::new();
        let mut ieee_neighbors_map: HashMap<MacAddr, Vec<IEEE1905Neighbor>> = HashMap::new();
        let mut non_ieee_neighbors_map: HashMap<MacAddr, Vec<MacAddr>> = HashMap::new();
        let mut device_bridging_capability = None;
        let mut supported_service = None;
        let mut end_of_message_found = false;
        let mut device_vendor = Ieee1905DeviceVendor::Unknown;

        for tlv in tlvs {
            match IEEE1905TLVType::from_u8(tlv.tlv_type) {
                IEEE1905TLVType::AlMacAddress => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed)) = AlMacAddress::parse(value) {
                            remote_al_mac = Some(parsed.al_mac_address);
                            tracing::debug!("Extracted AL MAC Address: {}", parsed.al_mac_address);
                        }
                    }
                }
                IEEE1905TLVType::VendorSpecificInfo => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed_vs)) = VendorSpecificInfo::parse(value, tlv.tlv_length)
                        {
                            tracing::trace!(
                                "VendorSpecific TLV found: OUI={:02x}:{:02x}:{:02x}, len={}",
                                parsed_vs.oui[0],
                                parsed_vs.oui[1],
                                parsed_vs.oui[2],
                                parsed_vs.vendor_data.len()
                            );

                            if parsed_vs.oui == COMCAST_OUI
                                && parsed_vs.vendor_data.starts_with(COMCAST_QUERY_TAG)
                            {
                                device_vendor = Ieee1905DeviceVendor::Rdk;
                                tracing::debug!(
                                    "Matched Comcast VendorSpecific TLV (00:90:96 / 00 01 00)."
                                );
                            }
                        }
                    }
                }
                IEEE1905TLVType::DeviceInformation => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed)) = DeviceInformation::parse(value, tlv.tlv_length) {
                            remote_al_mac = Some(parsed.al_mac_address);
                            interfaces.extend(parsed.local_interface_list.into_iter().map(
                                |iface| Ieee1905InterfaceData {
                                    mac: iface.mac_address,
                                    media_type: iface.media_type,
                                    bridging_flag: false,
                                    bridging_tuple: None,
                                    vlan: None,
                                    metric: None,
                                    non_ieee1905_neighbors: None,
                                    ieee1905_neighbors: None,
                                },
                            ));
                        }
                    }
                }
                IEEE1905TLVType::Ieee1905NeighborDevices => {
                    if let Some(ref value) = tlv.tlv_value {
                        let devices_count = ((tlv.tlv_length - 6) / 7) as usize;
                        if let Ok((_, parsed)) = Ieee1905NeighborDevice::parse(value, devices_count) {
                            ieee_neighbors_map.insert(parsed.local_mac_address, parsed.neighborhood_list);
                        }
                    }
                }
                IEEE1905TLVType::NonIeee1905NeighborDevices => {
                    if let Some(ref value) = tlv.tlv_value {
                        let devices_count = (tlv.tlv_length - 6) / 6;
                        if let Ok((_, parsed)) = NonIeee1905NeighborDevices::parse(value, devices_count) {
                            non_ieee_neighbors_map.insert(parsed.local_mac_address, parsed.neighborhood_list);
                        }
                    }
                }
                IEEE1905TLVType::DeviceBridgingCapability => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed)) = DeviceBridgingCapability::parse(value) {
                            device_bridging_capability = Some(parsed);
                        }
                    }
                }
                IEEE1905TLVType::SupportedService => {
                    if let Some(value) = tlv.tlv_value.as_ref() {
                        if let Ok((_, parsed)) = SupportedService::parse(value) {
                            supported_service = Some(parsed);
                        }
                    }
                }
                IEEE1905TLVType::EndOfMessage => {
                    end_of_message_found = true;
                }
                _ => {}
            }
        }

        if !end_of_message_found {
            tracing::warn!("Missing EndOfMessage TLV. Discarding Topology Response.");
            return true;
        }

        let Some(remote_al_mac_address) = remote_al_mac else {
            tracing::warn!("Topology Response missing AL MAC. Discarding.");
            return true;
        };

        if !ieee_neighbors_map.is_empty() {
            for iface in &mut interfaces {
                if let Some(neighs) = ieee_neighbors_map.get(&iface.mac) {
                    iface.ieee1905_neighbors = Some(neighs.clone());
                }
            }
        }

        let topology_db =
            TopologyDatabase::get_instance(self.local_al_mac, self.interface_name.clone()).await;

        let expected_id = topology_db
            .get_device(remote_al_mac_address)
            .await
            .and_then(|n| n.metadata.message_id);

        match expected_id {
            Some(exp) if exp == message_id => {}
            Some(exp) => {
                tracing::warn!(
                    expected = exp,
                    got = message_id,
                    al_mac = %remote_al_mac_address,
                    "Topology Response message_id mismatch → fallback to SDU"
                );
                return false;
            }
            None => {
                tracing::warn!(
                    al_mac = %remote_al_mac_address,
                    "No in-flight query for this node (missing expected message_id) → fallback to SDU"
                );
                return false;
            }
        }

        for interface in interfaces.iter_mut() {
            interface.ieee1905_neighbors = ieee_neighbors_map.remove(&interface.mac);
            interface.non_ieee1905_neighbors = non_ieee_neighbors_map.remove(&interface.mac);
        }

        if let Some(device_bridging_capability) = device_bridging_capability {
            let mut bridge_index_by_interface = HashMap::new();
            for (index, macs) in device_bridging_capability.bridging_tuples_list.iter().enumerate() {
                for mac in macs.bridging_mac_list.iter() {
                    bridge_index_by_interface.insert(mac, index as u8);
                }
            }
            
            for interface in interfaces.iter_mut() {
                if let Some(bridge_index) = bridge_index_by_interface.get(&interface.mac) {
                    interface.bridging_flag = true;
                    interface.bridging_tuple = Some(*bridge_index);
                }
            }
        }

        let registry_role = supported_service.and_then(|e| {
            if e.services.contains(&SupportedService::CONTROLLER) {
                return Some(Role::Registrar);
            }
            if e.services.contains(&SupportedService::AGENT) {
                return Some(Role::Enrollee);
            }
            None
        });

        let updated_device_data = Ieee1905DeviceData {
            al_mac: remote_al_mac_address,
            destination_mac: None,
            local_interface_list: Some(interfaces.clone()),
            registry_role,
        };

        let event = topology_db
            .update_ieee1905_topology(
                updated_device_data,
                UpdateType::ResponseReceived,
                Some(message_id),
                None,
                Some(device_vendor),
            )
            .await;

        tracing::info!(
            "Topology Response processed: AL_MAC={} MESSAGE_ID={}",
            remote_al_mac_address,
            message_id
        );

        match event {
            TransmissionEvent::SendTopologyNotification(_destination_mac) => {
                tracing::debug!(
                    al_mac = %remote_al_mac_address,
                    "Sending Topology Notification because topology changed"
                );

                let forwarding_interface_mac = topology_db.get_forwarding_interface_mac().await;

                cmdu_topology_notification_transmission(
                    self.interface_name.clone(),
                    Arc::clone(&self.sender),
                    Arc::clone(&self.message_id_generator),
                    self.local_al_mac,
                    forwarding_interface_mac,
                )
                .await;
            }
            TransmissionEvent::None => {
                tracing::debug!(
                    al_mac = %remote_al_mac_address,
                    "Topology update did not require sending notification"
                );
            }
            _ => {}
        };

        true
    }

    /// Handles and logs TLVs from the CMDU payload for Topology Notification.
    async fn handle_topology_notification(&self, tlvs: &[TLV], message_id: u16) -> bool {
        tracing::debug!(
            "Handling Topology Notification CMDU with Message ID: {} from interface {}",
            message_id,
            self.interface_name
        );

        let mut remote_al_mac: Option<MacAddr> = None;
        let mut end_of_message_found = false;
        let mut device_vendor = Ieee1905DeviceVendor::Unknown;

        for (index, tlv) in tlvs.iter().enumerate() {
            let tlv_type = IEEE1905TLVType::from_u8(tlv.tlv_type);
            tracing::debug!(
                index,
                tlv_type = ?tlv_type,
                length = tlv.tlv_length,
                "Processing TLV"
            );

            match tlv_type {
                IEEE1905TLVType::AlMacAddress => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed)) = AlMacAddress::parse(value) {
                            remote_al_mac = Some(parsed.al_mac_address);
                            tracing::debug!("Extracted AL MAC Address: {}", parsed.al_mac_address);
                        }
                    }
                }
                IEEE1905TLVType::VendorSpecificInfo => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed_vs)) = VendorSpecificInfo::parse(value, tlv.tlv_length)
                        {
                            tracing::trace!(
                                "VendorSpecific TLV found: OUI={:02x}:{:02x}:{:02x}, len={}",
                                parsed_vs.oui[0],
                                parsed_vs.oui[1],
                                parsed_vs.oui[2],
                                parsed_vs.vendor_data.len()
                            );

                            if parsed_vs.oui == COMCAST_OUI
                                && parsed_vs.vendor_data.starts_with(COMCAST_QUERY_TAG)
                            {
                                device_vendor = Ieee1905DeviceVendor::Rdk;
                                tracing::debug!(
                                    "Matched Comcast VendorSpecific TLV (00:90:96 / 00 01 00)."
                                );
                            }
                        }
                    }
                }
                IEEE1905TLVType::EndOfMessage => {
                    end_of_message_found = true;
                    tracing::debug!("End of CMDU Message found");
                }
                _ => tracing::trace!("Ignoring TLV type {:?}. Raw: {:?}", tlv_type, tlv.tlv_value),
            }
        }

        if !end_of_message_found {
            tracing::error!(
                "Topology Notification CMDU missing EndOfMessage TLV → discarding message."
            );
            return true;
        }

        if device_vendor != Ieee1905DeviceVendor::Rdk {
            warn!("Topology Notification missing required Comcast VendorSpecific TLV → fallback to SDU.");
            return false;
        }

        let Some(remote_al_mac_address) = remote_al_mac else {
            tracing::warn!(
                "Topology Notification has Comcast VendorSpecific TLV but missing AL MAC → fallback to SDU."
            );
            return false;
        };

        let topology_db =
            TopologyDatabase::get_instance(self.local_al_mac, self.interface_name.clone()).await;

        let received_device_data = Ieee1905DeviceData {
            al_mac: remote_al_mac_address,
            destination_mac: None,
            local_interface_list: None,
            registry_role: None,
        };

        let event = topology_db
            .update_ieee1905_topology(
                received_device_data,
                UpdateType::NotificationReceived,
                Some(message_id),
                None,
                Some(device_vendor),
            )
            .await;

        tracing::info!(
            "Topology Notification processed from AL_MAC={}",
            remote_al_mac_address
        );

        match event {
            TransmissionEvent::SendTopologyQuery(dest_mac) => {
                let forwarding_interface = topology_db.get_forwarding_interface_mac().await;

                cmdu_topology_query_transmission(
                    self.interface_name.clone(),
                    self.sender.clone(),
                    self.message_id_generator.clone(),
                    self.local_al_mac,
                    dest_mac,
                    forwarding_interface,
                )
                .await;
            }
            TransmissionEvent::None => {
                tracing::debug!("No transmission event triggered by Topology Notification");
            }
            _ => {
                tracing::warn!("Unexpected TransmissionEvent in handle_topology_notification");
            }
        };

        true
    }

    /// Handles APAutoconfigSearchCMDU
    async fn handle_ap_auto_config_search(&self, tlvs: &[TLV], message_id: u16) -> bool {
        tracing::debug!(
            "Handling Ap Auto Config Response CMDU with Message ID: {} from interface {}",
            message_id,
            self.interface_name
        );

        let mut remote_al_mac: Option<MacAddr> = None;
        let mut end_of_message_found = false;
        let mut ap_auto_config_search_found = false;
        let mut registry_role: Option<Role> = None;

        for tlv in tlvs {
            match IEEE1905TLVType::from_u8(tlv.tlv_type) {
                IEEE1905TLVType::AlMacAddress => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, parsed)) = AlMacAddress::parse(value) {
                            remote_al_mac = Some(parsed.al_mac_address);
                        }
                    }
                }
                IEEE1905TLVType::SearchedRole => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, _parsed)) = SearchedRole::parse(value, tlv.tlv_length) {
                            registry_role = Some(Role::Enrollee);
                            ap_auto_config_search_found = true;
                        }
                    }
                }
                IEEE1905TLVType::EndOfMessage => {
                    end_of_message_found = true;
                }
                _ => {}
            }
        }

        if !end_of_message_found {
            tracing::warn!("Missing EndOfMessage TLV. Ignoring.");
            return true;
        }
        if !ap_auto_config_search_found {
            tracing::warn!("Missing Ap Auto Config search TLV. Ignoring.");
            return true;
        }

        if let (Some(remote_al_mac_address), Some(reg_role)) = (remote_al_mac, registry_role) {
            let topology_db =
                TopologyDatabase::get_instance(self.local_al_mac, self.interface_name.clone())
                    .await;

            let updated_device_data = Ieee1905DeviceData {
                al_mac: remote_al_mac_address,
                destination_mac: None,
                local_interface_list: None,
                registry_role: Some(reg_role),
            };

            let _event = {
                topology_db
                    .update_ieee1905_topology(
                        updated_device_data,
                        UpdateType::AutoConfigSearch,
                        Some(message_id),
                        None,
                        None,
                    )
                    .await
            };

            debug!(
                "Topology Database updated: AL_MAC={} ROLE={:?}",
                remote_al_mac_address, reg_role
            );
        } else {
            tracing::warn!(
                "AP auto config  search CMDU processing failed: AL_MAC or Role not found in TLVs"
            );
        }
        true
    }

    /// Handle APAutconfigResposne CMDU
    async fn handle_ap_auto_config_response(
        &self,
        tlvs: &[TLV],
        message_id: u16,
        source_mac: MacAddr,
    ) -> bool {
        tracing::debug!(
            "Handling Ap Auto Config Response CMDU with Message ID: {} from interface {}",
            message_id,
            self.interface_name
        );

        let remote_al_mac: Option<MacAddr> = Some(source_mac);
        let mut end_of_message_found = false;
        let mut ap_auto_config_response_found = false;
        let mut registry_role: Option<Role> = None;

        for tlv in tlvs {
            match IEEE1905TLVType::from_u8(tlv.tlv_type) {
                IEEE1905TLVType::SupportedRole => {
                    if let Some(ref value) = tlv.tlv_value {
                        if let Ok((_, _parsed)) = SupportedRole::parse(value, tlv.tlv_length) {
                            registry_role = Some(Role::Registrar);
                            ap_auto_config_response_found = true;
                        }
                    }
                }
                IEEE1905TLVType::EndOfMessage => {
                    end_of_message_found = true;
                }
                _ => {}
            }
        }

        if !end_of_message_found {
            tracing::warn!("Missing EndOfMessage TLV. Ignoring.");
            return true;
        }
        if !ap_auto_config_response_found {
            tracing::warn!("Missing Ap Auto Config Response TLV. Ignoring.");
            return true;
        }

        if let (Some(remote_al_mac_address), Some(reg_role)) = (remote_al_mac, registry_role) {
            let topology_db =
                TopologyDatabase::get_instance(self.local_al_mac, self.interface_name.clone())
                    .await;

            let updated_device_data = Ieee1905DeviceData {
                al_mac: remote_al_mac_address,
                destination_mac: None,
                local_interface_list: None,
                registry_role: Some(reg_role),
            };

            let _event = {
                topology_db
                    .update_ieee1905_topology(
                        updated_device_data,
                        UpdateType::AutoConfigResponse,
                        Some(message_id),
                        None,
                        None,
                    )
                    .await
            };

            tracing::info!(
                "Topology Response Processed: Updated Node → AL_MAC={} MESSAGE_ID={} ROLE={:?}",
                remote_al_mac_address,
                message_id,
                reg_role
            );
        } else {
            tracing::warn!(
                "AP auto config  response CMDU processing failed: AL_MAC or Registry Role not found in TLVs"
            );
        }
        true
    }

    pub async fn handle_sdu_from_cmdu_reception(
        &self,
        tlvs: &[TLV],
        message_id: u16,
        message_type: u16,
        source_mac: MacAddr,
        destination_mac: MacAddr,
    ) -> anyhow::Result<()> {
        let mut end_of_message_found = false;
        let tlv_no = tlvs.len();
        trace!(
            "Handling SDU from CMDU with Message ID: {}, from interface {}, message type {}, no of tlvs {}",
            message_id, self.interface_name, message_type, tlv_no
        );
        trace!(
            "Handle SDU from CMDU source_mac {source_mac:?} destination_mac {destination_mac:?}"
        );
        debug!(
            "Handling SDU from CMDU with Message ID: {}, from interface {}",
            message_id, self.interface_name
        );

        for (index, tlv) in tlvs.iter().enumerate() {
            trace!(
                index,
                tlv_type = ?IEEE1905TLVType::from_u8(tlv.tlv_type),
                length = tlv.tlv_length,
                "Processing TLV"
            );

            match IEEE1905TLVType::from_u8(tlv.tlv_type) {
                IEEE1905TLVType::EndOfMessage => {
                    end_of_message_found = true;
                    trace!("End of CMDU Message found");
                }
                _ => warn!(
                    "Unknown TLV Type: {:#x?}, Raw Data: {:?}",
                    tlv.tlv_type, tlv.tlv_value
                ),
            }
        }

        if !end_of_message_found {
            error!("SDU from CMDU is missing the required End of Message TLV. Ignoring CMDU.");
            return Ok(());
        }

        if destination_mac != IEEE1905_CONTROL_ADDRESS && destination_mac != self.local_al_mac {
            tracing::debug!("Skipping SDU from CMDU as destination mac {destination_mac:?} is different as local al mac {}",self.local_al_mac);
            return Ok(());
        }

        let topology_db =
            TopologyDatabase::get_instance(source_mac, self.interface_name.clone()).await;

        if let Some(updated_node) = topology_db.get_device(source_mac).await {
            trace!("Node: {updated_node:?}");
            if updated_node.metadata.node_state_local == Some(StateLocal::ConvergedLocal)
                && updated_node.metadata.node_state_remote == Some(StateRemote::ConvergedRemote)
                && updated_node.device_data.al_mac != self.local_al_mac
            {
                debug!(remote= %source_mac,
                        metadata = ?updated_node.metadata,
                        "Sending the serviceAccessPointDataIndication");
                let mut serialized_payload: Vec<u8> = vec![];
                for tlv in tlvs {
                    serialized_payload.extend(tlv.serialize());
                }

                let sdu = SDU {
                    source_al_mac_address: self.local_al_mac,
                    destination_al_mac_address: source_mac,
                    is_fragment: 0,
                    is_last_fragment: 0,
                    fragment_id: 0,
                    payload: CMDU {
                        message_version: 0x01,
                        reserved: 0x00,
                        message_type,
                        message_id,
                        fragment: 0,
                        flags: 0x80,
                        payload: serialized_payload,
                    }
                    .serialize(),
                };
                tracing::trace!("Sending SDU from CMDU: <{sdu:?}>");
                service_access_point_data_indication(&sdu).await?;
            } else {
                trace!(
                    "Skipping as not in converged mode or update device data equal to local al mac"
                );
            }
        } else {
            trace!("Cannot find device for {} topology_db", source_mac);
        }
        Ok(())
    }

    async fn filter_incoming_cmdu(&self, cmdu: &CMDU) -> bool {
        let db = TopologyDatabase::get_instance(
            self.local_al_mac,
            self.interface_name.clone(),
        ).await;

        let role = db.get_actual_local_role().await;
        let role_restricted_types: &[CMDUType] = match role {
            Some(Role::Registrar) => &[CMDUType::ApAutoConfigResponse],
            Some(Role::Enrollee) => {
                match !db.has_remote_controllers().await {
                    true => &[], // an agent can act as controller when controller is down
                    false => &[CMDUType::ApAutoConfigSearch],
                }
            },
            None => &[],
        };

        if role_restricted_types.contains(&CMDUType::from_u16(cmdu.message_type)) {
            warn!("CMDU type {:04x} blocked based on the local role {role:?}", cmdu.message_type);
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmdu_codec::tests::make_dummy_cmdu;
    use crate::cmdu_message_id_generator::get_message_id_generator;
    use crate::cmdu_reassembler::CmduReassemblyError;
    use crate::interface_manager::get_forwarding_interface_name;
    use crate::interface_manager::get_local_al_mac;
    use tokio::sync::Mutex;

    // Verify CMDU fragmentation and push_fragment function
    #[tokio::test]
    async fn test_fragmentation_and_push_fragment_function() {
        // Prepare CMDU with several different TLVs
        let cmdu = make_dummy_cmdu(vec![
            100 - 8 - 3,
            200 - 3,
            300 - 3,
            400 - 3,
            500 - 3,
            700,
            800,
            900,
            600,
            1000,
            1100,
            1200 - 8 - 3,
            300 - 3,
            1400 - 8 - 3,
            100 - 3,
            1500 - 3 - 8,
        ]);

        // Prepare source MAC address
        let source_mac = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        // Do the CMDU fragmentation
        let fragments = cmdu.clone().fragment(1500);

        // Prepare a CmduReassembler instance
        let cmdu_reasm = CmduReassembler::new();

        let mut reassembled: Option<CMDU> = None;

        // Verify every CMDU fragment after fragmentation
        for (i, fragment) in fragments.iter().enumerate() {
            // Verify that the size of CMDU meets minimum size requirements
            if fragment.is_last_fragment() {
                // Differentiate between last-first and the last-but-not-first CMDU fragments
                if i == 0 {
                    // First and at the same time last CMDU fragment (the only fragment in CMDU chain) in case of size based fragmentation should have the minimal size of CMDU header + TLV header without any TLV payload
                    assert!(
                        fragment.total_size() >= 8 + 3,
                        "Fragment {0} should be at least 8+3 bytes but is {1} bytes long",
                        i,
                        fragment.total_size()
                    );
                } else {
                    // Last CMDU fragment which is not first one - in case of size based fragmentation should have minimal size of CMDU header + 1 byte
                    assert!(
                        fragment.total_size() >= 8 + 1,
                        "Fragment {0} should be at least 8+1 bytes but is {1} bytes long",
                        i,
                        fragment.total_size()
                    );
                }
            }

            // Verify that the current CMDU fragment size meets the maximum allowed size of 1500 bytes
            assert!(
                fragment.total_size() <= 1500,
                "Fragment {} should have maximum 1500 bytes but is {} bytes long",
                i,
                fragment.total_size()
            );

            // Add current CMDU fragment to the list of already reassembled fragments
            match cmdu_reasm.push_fragment(source_mac, fragment.clone()).await {
                Some(Ok(full_cmdu)) => {
                    debug!("CMDU completely reassembled");
                    reassembled = Some(full_cmdu);
                }
                Some(Err(e)) => {
                    error!("Error reassembling CMDU: {:?}", e);
                }
                None => {
                    trace!("Fragment stored. Waiting for more...");
                }
            }
        }

        // Expect success comparing payload of fragmented and then reassembled CMDU with the original one
        assert_eq!(
            reassembled.unwrap().payload,
            cmdu.payload,
            "Reassembled payload should match original"
        );
    }

    #[tokio::test]
    async fn test_custom_fragments() {
        // Prepare contents of 1st part of CMDU
        let cmdu_frag_0: Vec<u8> = vec![
            0, 0, 0, 7, 10, 0, 0, 0, 1, 0, 6, 2, 66, 192, 168, 100, 3, 13, 0, 1, 0, 14, 0, 1, 0,
            128, 0, 2, 1, 1, 129, 0, 2, 1, 0, 179, 0, 1, 3, 11, 0, 42, 0, 16, 24, 1, 0, 36, 1, 160,
            45, 19, 6, 101, 36, 160, 45, 19, 6, 101, 33, 5, 49, 56, 56, 54, 55, 16, 49, 55, 54, 52,
            51, 57, 52, 51, 51, 50, 55, 50, 51, 52, 54, 49, 11, 5, 220, 69, 90, 80, 227, 174, 89,
            89, 89, 89, 231, 231, 136, 23, 173, 241, 121, 101, 52, 68, 239, 171, 57, 134, 222, 196,
            202, 219, 24, 224, 195, 81, 238, 91, 71, 85, 155, 120, 202, 193, 117, 167, 67, 189,
            227, 210, 119, 36, 199, 208, 246, 134, 58, 103, 120, 117, 238, 88, 187, 27, 45, 17, 39,
            133, 230, 218, 114, 169, 125, 64, 34, 250, 54, 225, 43, 63, 204, 28, 59, 97, 191, 140,
            140, 96, 61, 163, 43, 123, 150, 2, 15, 83, 160, 74, 161, 64, 152, 240, 144, 227, 146,
            153, 76, 91, 212, 126, 170, 119, 1, 136, 137, 45, 30, 171, 165, 96, 58, 30, 65, 160,
            219, 105, 52, 153, 197, 179, 134, 116, 81, 20, 195, 106, 42, 95, 242, 83, 230, 126, 97,
            185, 217, 72, 64, 36, 84, 129, 189, 17, 68, 226, 44, 43, 112, 61, 92, 130, 239, 77, 55,
            0, 193, 228, 255, 248, 51, 108, 214, 127, 246, 135, 141, 7, 135, 195, 222, 237, 192,
            43, 175, 52, 7, 76, 78, 83, 215, 56, 41, 166, 161, 146, 10, 27, 238, 155, 20, 111, 199,
            117, 189, 234, 180, 32, 25, 183, 8, 187, 185, 84, 126, 43, 7, 196, 30, 12, 197, 160,
            142, 130, 224, 79, 144, 26, 1, 180, 88, 35, 16, 215, 211, 113, 237, 81, 45, 184, 18,
            43, 131, 16, 205, 42, 175, 228, 204, 121, 199, 106, 67, 217, 215, 159, 65, 65, 248,
            207, 227, 250, 138, 216, 78, 138, 44, 232, 23, 233, 234, 40, 8, 135, 47, 153, 93, 186,
            56, 190, 114, 9, 127, 12, 118, 251, 183, 20, 101, 218, 174, 155, 110, 25, 49, 57, 48,
            207, 254, 20, 52, 233, 140, 55, 226, 162, 137, 232, 81, 198, 195, 65, 189, 11, 0, 194,
            122, 190, 244, 30, 92, 208, 40, 209, 196, 206, 222, 135, 161, 50, 228, 149, 242, 164,
            172, 58, 233, 80, 136, 226, 7, 95, 147, 150, 246, 4, 120, 119, 182, 29, 250, 249, 219,
            185, 186, 135, 118, 223, 161, 217, 227, 233, 49, 73, 77, 91, 116, 255, 171, 3, 194, 90,
            120, 144, 136, 23, 158, 191, 10, 211, 135, 155, 251, 209, 126, 198, 52, 57, 173, 231,
            47, 212, 44, 128, 99, 142, 78, 216, 14, 3, 204, 18, 114, 109, 66, 218, 52, 69, 229,
            114, 95, 151, 115, 197, 71, 151, 24, 113, 184, 34, 106, 192, 104, 97, 155, 73, 212,
            209, 153, 178, 231, 111, 151, 66, 84, 94, 149, 0, 152, 51, 190, 106, 47, 235, 108, 232,
            139, 172, 77, 77, 91, 143, 113, 133, 207, 45, 251, 33, 43, 72, 168, 111, 172, 84, 150,
            105, 181, 58, 55, 222, 47, 186, 119, 135, 17, 219, 129, 186, 121, 197, 158, 17, 239,
            247, 75, 28, 120, 159, 65, 9, 123, 237, 246, 242, 76, 3, 24, 126, 56, 79, 170, 152,
            173, 59, 168, 93, 42, 80, 225, 236, 92, 233, 233, 44, 173, 236, 44, 168, 17, 175, 53,
            255, 77, 5, 59, 252, 44, 141, 219, 139, 231, 199, 156, 102, 178, 209, 255, 202, 104,
            96, 78, 123, 74, 119, 204, 204, 253, 101, 135, 214, 79, 84, 76, 111, 8, 235, 242, 158,
            186, 98, 181, 227, 159, 88, 224, 30, 249, 195, 170, 181, 81, 77, 3, 143, 216, 123, 230,
            207, 48, 28, 234, 55, 79, 155, 147, 139, 79, 14, 63, 77, 0, 210, 208, 125, 175, 60, 53,
            114, 0, 49, 192, 193, 85, 225, 195, 109, 230, 72, 35, 145, 206, 111, 135, 37, 165, 150,
            44, 209, 81, 48, 155, 114, 135, 33, 109, 106, 40, 63, 74, 117, 88, 113, 245, 212, 122,
            132, 80, 183, 157, 2, 68, 19, 62, 24, 23, 166, 217, 49, 135, 233, 223, 183, 5, 141,
            170, 239, 142, 120, 137, 168, 13, 149, 35, 253, 125, 77, 19, 139, 30, 57, 133, 246,
            103, 84, 160, 133, 158, 78, 99, 8, 203, 99, 111, 250, 109, 61, 45, 1, 37, 102, 196,
            216, 172, 71, 242, 109, 239, 217, 229, 195, 184, 246, 109, 51, 209, 143, 116, 58, 105,
            46, 34, 212, 69, 116, 135, 17, 95, 210, 163, 118, 124, 223, 213, 13, 255, 98, 114, 156,
            87, 218, 68, 204, 63, 241, 183, 111, 63, 31, 2, 239, 103, 136, 43, 118, 85, 245, 227,
            15, 111, 182, 95, 203, 77, 70, 176, 173, 174, 178, 243, 105, 200, 61, 144, 138, 49,
            187, 46, 195, 123, 15, 156, 20, 207, 41, 219, 205, 234, 109, 29, 194, 87, 59, 81, 198,
            205, 162, 113, 43, 87, 41, 148, 249, 82, 89, 9, 181, 158, 179, 253, 103, 90, 59, 124,
            105, 157, 219, 199, 118, 150, 20, 194, 127, 152, 13, 4, 174, 74, 221, 158, 171, 83, 82,
            181, 14, 129, 56, 190, 9, 97, 37, 56, 198, 66, 181, 88, 245, 243, 31, 146, 213, 136,
            169, 88, 86, 119, 82, 186, 57, 58, 203, 42, 107, 106, 77, 24, 153, 36, 144, 50, 199, 8,
            16, 246, 246, 215, 153, 5, 236, 169, 189, 35, 88, 11, 193, 151, 227, 130, 232, 115, 1,
            146, 174, 31, 58, 53, 83, 223, 27, 241, 42, 247, 86, 213, 127, 69, 247, 99, 252, 113,
            146, 251, 212, 8, 32, 234, 123, 15, 123, 15, 244, 218, 237, 87, 136, 187, 56, 28, 124,
            156, 229, 185, 80, 151, 175, 6, 44, 8, 207, 31, 216, 135, 145, 72, 10, 15, 62, 84, 56,
            147, 241, 101, 237, 8, 67, 243, 134, 41, 67, 99, 74, 173, 250, 199, 149, 155, 184, 2,
            172, 152, 69, 43, 215, 83, 49, 11, 96, 61, 87, 76, 210, 32, 130, 168, 194, 174, 8, 114,
            119, 44, 103, 116, 251, 7, 227, 121, 203, 197, 106, 143, 60, 71, 158, 47, 182, 107,
            209, 32, 90, 254, 188, 158, 81, 240, 75, 134, 218, 97, 234, 239, 150, 176, 6, 115, 56,
            183, 194, 237, 197, 30, 16, 51, 70, 115, 2, 249, 172, 32, 102, 158, 197, 122, 52, 186,
            122, 81, 17, 161, 37, 214, 24, 221, 44, 163, 66, 255, 80, 55, 245, 31, 91, 171, 226,
            229, 91, 58, 177, 132, 8, 209, 224, 216, 79, 2, 127, 5, 46, 178, 20, 130, 156, 197,
            232, 83, 158, 98, 72, 103, 69, 30, 155, 194, 187, 218, 178, 176, 125, 81, 99, 185, 8,
            22, 97, 105, 137, 144, 227, 78, 244, 35, 113, 199, 43, 13, 229, 254, 185, 25, 65, 2,
            222, 251, 119, 130, 159, 21, 171, 156, 238, 45, 250, 192, 194, 36, 94, 91, 54, 232, 90,
            193, 169, 165, 168, 92, 12, 237, 193, 78, 130, 135, 81, 126, 150, 28, 192, 225, 74,
            213, 21, 95, 88, 105, 61, 163, 192, 171, 20, 187, 23, 47, 184, 18, 112, 96, 6, 162, 85,
            252, 39, 93, 20, 96, 77, 245, 48, 250, 244, 100, 155, 129, 185, 122, 41, 60, 3, 51,
            116, 68, 193, 7, 81, 163, 95, 192, 198, 242, 112, 57, 114, 86, 48, 14, 117, 225, 136,
            151, 178, 53, 180, 10, 128, 152, 222, 215, 90, 120, 11, 157, 177, 8, 85, 108, 156, 156,
            131, 48, 160, 37, 243, 39, 60, 158, 38, 251, 59, 50, 67, 11, 180, 252, 165, 156, 65,
            25, 162, 168, 14, 254, 11, 184, 253, 109, 171, 118, 170, 18, 21, 27, 29, 52, 239, 232,
            150, 204, 44, 98, 190, 158, 15, 207, 21, 8, 250, 184, 216, 4, 215, 201, 246, 129, 185,
            95, 9, 132, 78, 201, 160, 245, 19, 11, 85, 48, 117, 28, 50, 8, 250, 169, 146, 7, 111,
            45, 137, 221, 96, 159, 170, 78, 186, 53, 139, 227, 221, 33, 194, 77, 133, 19, 21, 2,
            141, 33, 222, 73, 127, 49, 5, 199, 245, 243, 169, 16, 118, 219, 165, 7, 128, 173, 227,
            220, 125, 195, 136, 134, 66, 86, 11, 221, 123, 199, 147, 218, 81, 89, 225, 26, 42, 81,
            52, 120, 3, 90, 243, 124, 1, 243, 85, 242, 202, 149, 69, 79, 90, 216, 225, 115, 19,
            141, 102, 107, 142, 16, 88, 64, 130, 220, 202, 216, 128, 9, 101, 161, 128, 227, 102,
            186, 219, 225, 68, 80, 122, 201, 218, 92, 27, 43, 62, 24, 96, 90, 207, 108, 47, 210, 9,
            154, 211, 46, 55, 178,
        ];

        // Parse 1st part of CMDU
        let cmdu_part_1 = CMDU::parse(cmdu_frag_0.as_slice()).unwrap().1;

        // Prepare contents of 2nd part of CMDU
        let cmdu_frag_1: Vec<u8> = vec![
            0, 0, 0, 7, 10, 0, 1, 128, 166, 69, 239, 84, 199, 3, 231, 246, 87, 92, 116, 30, 172,
            212, 47, 94, 202, 91, 30, 102, 59, 183, 203, 11, 143, 240, 107, 191, 226, 57, 76, 25,
            148, 28, 248, 239, 38, 132, 203, 203, 55, 100, 109, 120, 234, 107, 59, 195, 165, 216,
            87, 93, 115, 107, 212, 253, 110, 86, 8, 139, 253, 94, 239, 77, 61, 183, 176, 29, 209,
            231, 211, 217, 225, 249, 166, 46, 19, 137, 19, 121, 17, 254, 27, 220, 190, 234, 133,
            15, 0, 0, 0,
        ];

        // Parse 2nd part of CMDU
        let cmdu_part_2 = CMDU::parse(cmdu_frag_1.as_slice()).unwrap().1;

        // Prepare example MAC address
        let source_mac = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        // Combine both CMDU parts into vector
        let fragments: Vec<CMDU> = vec![cmdu_part_1, cmdu_part_2];

        // Prepare instance of CmduReassembler
        let cmdu_reasm = CmduReassembler::new();

        // Make instance of CMDU for reassembling CMDU fragments into one, final CMDU
        let mut reassembled: Option<CMDU> = None;

        // Iterate on all the CMDU fragments, check them and reassembly the original CMDU
        for (i, fragment) in fragments.iter().enumerate() {
            // Verify that the size of CMDU meets minimum size requirements
            if fragment.is_last_fragment() {
                // Differentiate between last-first and the last-but-not-first CMDU fragments
                if i == 0 {
                    // First and at the same time last CMDU fragment (the only fragment in CMDU chain) in case of size based fragmentation should have the minimal size of CMDU header + TLV header without any TLV payload
                    assert!(
                        fragment.total_size() >= 8 + 3,
                        "Fragment {0} should be at least 8+3 bytes but is {1} bytes long",
                        i,
                        fragment.total_size()
                    );
                } else {
                    // Last CMDU fragment which is not first one - in case of size based fragmentation should have minimal size of CMDU header + 1 byte
                    assert!(
                        fragment.total_size() >= 8 + 1,
                        "Fragment {0} should be at least 8+1 bytes but is {1} bytes long",
                        i,
                        fragment.total_size()
                    );
                }
            }

            // Verify that the current CMDU fragment size meets the maximum allowed size of 1500 bytes
            assert!(
                fragment.total_size() <= 1500,
                "Fragment {} should have maximum 1500 bytes but is {} bytes long",
                i,
                fragment.total_size()
            );

            // Reassembly current CMDU fragment with previously reassembled ones
            match cmdu_reasm.push_fragment(source_mac, fragment.clone()).await {
                Some(Ok(full_cmdu)) => {
                    debug!("CMDU completely reassembled");
                    reassembled = Some(full_cmdu);
                }
                Some(Err(e)) => {
                    error!("Error reassembling CMDU: {:?}", e);
                }
                None => {
                    trace!("Fragment stored. Waiting for more...");
                }
            }
        }
        // Expect success of reassembling CMDU from CMDU fragments
        assert!(reassembled.is_some());
    }

    // Verify detection of oversized CMDU
    #[tokio::test]
    async fn test_handle_cmdu_function_for_oversized_cmdu() {
        // Prepare forwarding interface
        let interface_name = "eth0".to_string();
        let forwarding_interface =
            if let Some(iface) = get_forwarding_interface_name(interface_name.clone()) {
                tracing::info!("Forwarding interface: {}", iface);
                iface
            } else {
                tracing::debug!("No Ethernet interface found for forwarding, using default.");
                "eth_default".to_string() // Default interface name if none found
            };

        // Prepare sender
        let mutex_tx = Arc::new(Mutex::new(()));
        let sender = Arc::new(EthernetSender::new(
            &forwarding_interface,
            Arc::clone(&mutex_tx),
        ));

        // Prepare MessageIdGenerator instance
        let message_id_generator = get_message_id_generator().await;

        // Prepare AL MAC
        let al_mac = if let Some(mac) = get_local_al_mac(interface_name.clone()) {
            tracing::info!("AL MAC address: {}", mac);
            mac
        } else {
            tracing::debug!("No AL MAC ADDRESS calculated, using default.");
            MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // Default AL MAC if not found
        };

        // Prepare CMDUHandler
        let cmdu_handler = CMDUHandler::new(
            Arc::clone(&sender),
            Arc::clone(&message_id_generator),
            al_mac,
            forwarding_interface.clone(),
        )
        .await;

        // Prepare an oversized CMDU exceeding MTU by one byte
        let cmdu = make_dummy_cmdu(vec![1500 - 8 - 3 + 1]);

        // Prepare both MAC addresses: source and destination one
        let source_mac = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let destination_mac = MacAddr::new(0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc);

        // Expect panic in handle_cmdu() as the CMDU size is prepared to have 1501 bytes
        assert!(cmdu_handler
            .handle_cmdu(&cmdu, source_mac, destination_mac)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_recognition_of_duplicate_fragment() {
        let mut cmdu0 = make_dummy_cmdu(vec![10, 20]);
        let mut cmdu1 = make_dummy_cmdu(vec![30, 40]);
        let mut cmdu2 = make_dummy_cmdu(vec![50, 60]);

        cmdu0.fragment = 0;
        cmdu1.fragment = 1;
        cmdu2.fragment = 1; // duplicated fragment No. 1
        cmdu2.flags = 0x80; // set last fragment flag

        let source_mac = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let fragments = vec![cmdu0, cmdu1, cmdu2];
        let cmdu_reasm = CmduReassembler::new();

        for fragment in fragments.iter() {
            match cmdu_reasm.push_fragment(source_mac, fragment.clone()).await {
                Some(Ok(_)) => {
                    panic!("DuplicatedFragment error expected but CMDU is completely reassembled");
                }
                Some(Err(e)) => {
                    assert_eq!(e, CmduReassemblyError::DuplicatedFragment);
                    error!("Error reassembling CMDU: {:?}", e);
                }
                None => {
                    trace!("Fragment stored. Waiting for more...");
                }
            }
        }
    }
}
