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

use bytes::Bytes;
use clap::Parser;
use futures::{SinkExt, StreamExt};
use ieee1905::cmdu_codec::*;
use ieee1905::registration_codec::{
    AlServiceRegistrationRequest, AlServiceRegistrationResponse, ServiceOperation, ServiceType,
};
use ieee1905::sdu_codec::SDU;
use ieee1905::topology_manager::{Ieee1905DeviceData, TopologyDatabase, UpdateType};
use pnet::datalink::*;
use std::process::exit;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::time::{Duration, sleep, timeout};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

async fn update_observed_topology(topology_db: Option<&Arc<TopologyDatabase>>, sdu: &SDU) {
    let Some(topology_db) = topology_db else {
        return;
    };

    let device_data = Ieee1905DeviceData::new(
        sdu.source_al_mac_address,
        sdu.source_al_mac_address,
        Some(sdu.destination_al_mac_address),
        sdu.source_al_mac_address,
        None,
        None,
    );

    topology_db
        .update_ieee1905_topology(device_data, UpdateType::DiscoveryReceived, None, None, None)
        .await;
}

async fn update_observed_topology_from_bytes(
    topology_db: Option<&Arc<TopologyDatabase>>,
    bytes: &[u8],
) {
    if let Ok((_, sdu)) = SDU::parse(bytes) {
        update_observed_topology(topology_db, &sdu).await;
    }
}

fn build_tlv(tlv_type: IEEE1905TLVType, value: Option<Vec<u8>>) -> ieee1905::cmdu::TLV {
    ieee1905::cmdu::TLV {
        tlv_type: tlv_type.to_u8(),
        tlv_length: value.as_ref().map_or(0, Vec::len) as u16,
        tlv_value: value,
    }
}

fn prepare_ap_autoconfig_request_sdu(
    r: &AlServiceRegistrationResponse,
    message_id: u16,
) -> Vec<u8> {
    let src_mac_addr = r.al_mac_address_local;
    let mut payload = Vec::new();
    payload.extend(
        build_tlv(
            IEEE1905TLVType::AlMacAddress,
            Some(src_mac_addr.octets().to_vec()),
        )
        .serialize(),
    );
    payload.extend(build_tlv(IEEE1905TLVType::SearchedRole, Some(vec![0x00])).serialize());
    payload.extend(build_tlv(IEEE1905TLVType::EndOfMessage, None).serialize());

    let cmdu = CMDU {
        message_version: MessageVersion::Version2013.to_u8(),
        reserved: 0,
        message_type: CMDUType::ApAutoConfigSearch.to_u16(),
        message_id,
        fragment: 0,
        flags: 0x80,
        payload,
    };

    SDU {
        source_al_mac_address: src_mac_addr,
        destination_al_mac_address: IEEE1905_CONTROL_ADDRESS,
        is_fragment: 0,
        is_last_fragment: 1,
        fragment_id: 0,
        payload: cmdu.serialize(),
    }
    .serialize()
}

fn is_ap_autoconfig_response(sdu: &SDU) -> bool {
    let Ok((_, cmdu)) = CMDU::parse(&sdu.payload) else {
        return false;
    };

    if cmdu.message_type != CMDUType::ApAutoConfigResponse.to_u16() {
        return false;
    }

    let Ok(tlvs) = cmdu.get_tlvs() else {
        return false;
    };

    tlvs.iter()
        .any(|tlv| tlv.tlv_type == IEEE1905TLVType::SupportedFreqBand.to_u8())
}

fn _prepare_test_packet_with_payload(
    r: &AlServiceRegistrationResponse,
    payload: Bytes,
    message_id: u16,
) -> Vec<u8> {
    let al_mac = r.al_mac_address_local;

    let mut res = match CMDU::parse(&payload[..]) {
        Ok(tuple) => tuple.1,
        Err(err) => {
            panic!("Failed to parse CMDU {err:?}");
        }
    };

    println!("Parsed CMDU: {:?}", res);

    println!("After cmdu parse: {res:?}");
    // Hardcoded message type to first unknown
    res.message_type = 0x0007;
    // Override message id
    res.message_id = message_id;
    println!("Changed message type {res:?}");
    let sdu = SDU {
        source_al_mac_address: al_mac,
        destination_al_mac_address: MacAddr::new(0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02),
        is_fragment: 0,
        is_last_fragment: 1,
        fragment_id: 0,
        payload: res.serialize(),
    };

    sdu.serialize()
}

fn prepare_payload_with_small_tlv(r: &AlServiceRegistrationResponse, multicast: bool) -> Vec<u8> {
    // Here is whole SDU with autoconfig request taken from onewifi_em_agent_
    let src_mac_addr = r.al_mac_address_local;
    let mut dest_mac_addr: MacAddr = MacAddr::new(0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02);
    if multicast {
        dest_mac_addr = MacAddr::new(0x01, 0x80, 0xc2, 0x00, 0x00, 0x13);
    }
    let sdu_bytes: Vec<u8> = vec![
        src_mac_addr.0, // SDU source_al_mac_address
        src_mac_addr.1,
        src_mac_addr.2,
        src_mac_addr.3,
        src_mac_addr.4,
        src_mac_addr.5,
        dest_mac_addr.0, // SDU destination_al_mac_address
        dest_mac_addr.1,
        dest_mac_addr.2,
        dest_mac_addr.3,
        dest_mac_addr.4,
        dest_mac_addr.5,
        0x00, // SDU is_fragment
        0x01, // SDU is_last_fragment
        0x00, // SDU fragment_id
        // Start of CMDU
        0x00, // CMDU message_version
        0x00, // CMDU reserved
        0x00,
        0x04, // CMDU message_type - 0x0004 Vendor sepcific message
        0x00,
        0x01, // CMDU message_id
        0x00, // CMDU fragment
        0x80, // CMDU flags
        // Start of TLVs
        // TLV 1: 6-9 AL MAC address type TLV
        0x01, // TLV type 1: 6-9 AL MAC address
        0x00,
        0x06,           // TLV length
        src_mac_addr.0, // AL MAC address
        src_mac_addr.1,
        src_mac_addr.2,
        src_mac_addr.3,
        src_mac_addr.4,
        src_mac_addr.5,
        // TLV 2: type Vendor Specific
        0x0b, // TLV type: Vendor Specific
        0x00,
        0x50, // TLV len: 80 bytes
        // TLV 2 vendor specific payload (zeroed placeholder)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // TLV 3: End of message
        0x00,
        0x00,
        0x00,
    ];

    match SDU::parse(sdu_bytes.as_slice()) {
        Ok(tuple) => {
            println!("Successfully parsed long bytes");
            tuple.1.serialize()
        }
        Err(e) => {
            println!("Failed to parse long bytes {e:?}");
            vec![]
        }
    }
}

fn prepare_payload_with_huge_tlv(r: &AlServiceRegistrationResponse, multicast: bool) -> Vec<u8> {
    // Here is whole SDU with autoconfig request taken from onewifi_em_agent_
    let src_mac_addr = r.al_mac_address_local;
    let mut dest_mac_addr: MacAddr = MacAddr::new(0xee, 0x42, 0xc0, 0xa8, 0x64, 0x02);
    if multicast {
        dest_mac_addr = MacAddr::new(0x01, 0x80, 0xc2, 0x00, 0x00, 0x13);
    }
    let sdu_bytes: Vec<u8> = vec![
        src_mac_addr.0, // SDU source_al_mac_address
        src_mac_addr.1,
        src_mac_addr.2,
        src_mac_addr.3,
        src_mac_addr.4,
        src_mac_addr.5,
        dest_mac_addr.0, // SDU destination_al_mac_address
        dest_mac_addr.1,
        dest_mac_addr.2,
        dest_mac_addr.3,
        dest_mac_addr.4,
        dest_mac_addr.5,
        0x00, // SDU is_fragment
        0x01, // SDU is_last_fragment
        0x00, // SDU fragment_id
        // Start of CMDU
        0x00, // CMDU message_version
        0x00, // CMDU reserved
        0x00,
        0x04, // CMDU message_type: 4 - Vendor specific
        0x0a,
        0x00, // CMDU message_id
        0x00, // CMDU fragment
        0x00, // CMDU flags
        // Start of TLVs
        // TLV 1: 6-9 AL MAC address type TLV
        0x01, // TLV type 1: 6-9 AL MAC address
        0x00,
        0x06,           // TLV length
        src_mac_addr.0, // AL MAC address
        src_mac_addr.1,
        src_mac_addr.2,
        src_mac_addr.3,
        src_mac_addr.4,
        src_mac_addr.5,
        // TLV 2: 6-22 SearchedRole TLV
        0x0d, // TLV type: 6-22 SearchedRole
        0x00,
        0x01, // TLV length
        0x00, // TLV payload
        // TLV 3: 6-23 AutoconfigFreqBand TLV
        0x0e, // TLV type 14: 6-23 AutoconfigFreqBand
        0x00,
        0x01, // TLV length
        0x00, // TLV 6-23 AutoconfigFreqBand
        // TLV 4: supported service 17.2.1
        0x80,
        0x00,
        0x02, // TLV length
        0x01,
        0x01, // TLV supported service 17.2.1
        // TLV 5: searched service 17.2.2
        0x81,
        0x00,
        0x02, // TLV length
        0x01,
        0x00, // TLV searched service 17.2.2
        // TLV 6: One multiAP profile tlv 17.2.47
        0xb3,
        0x00,
        0x01, // TLV length
        0x03, // TLV 6 One multiAP profile tlv 17.2.47
        // TLV 7: type Vendor Specific
        0x0b, // TLV type: Vendor Specific
        0x05,
        0xdc, // TLV len: 1500 bytes
        // TLV 7 vendor specific payload (zeroed placeholder: 1500 bytes)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // End of zeroed 1500 bytes block

        // TLV 8: End of message
        0x00, // TLV type 0: 6-6 End of message type
        0x00,
        0x00,
    ];

    println!("SDU_BYTES: [{:?}] <{:?}>", sdu_bytes.len(), sdu_bytes);

    match SDU::parse(sdu_bytes.as_slice()) {
        Ok(tuple) => {
            println!("Successfully parsed long bytes");
            tuple.1.serialize()
        }
        Err(e) => {
            println!("Failed to parse long bytes {e:?}");
            vec![]
        }
    }
}

async fn test1(
    sap_control_path: &str,
    sap_data_path: &str,
    interface_name: &str,
    topology_ui: bool,
) -> anyhow::Result<()> {
    // Modify this filter for your tracing during run time
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace")); //add 'tokio=trace' to debug the runtime

    // To show logs in stdout
    let fmt_layer = fmt::layer().with_target(true).with_level(true);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();

    println!("Starting test1");

    let control_socket = match UnixStream::connect(&sap_control_path).await {
        Ok(unix_stream) => unix_stream,
        Err(e) => {
            println!("     Couldn't connect to control socket: {e:?}");
            return Err(e.into());
        }
    };
    println!("Connected to control socket");

    let mut framed_control_socket: Framed<UnixStream, LengthDelimitedCodec> =
        Framed::new(control_socket, LengthDelimitedCodec::new());

    let mut data_socket = match UnixStream::connect(&sap_data_path).await {
        Ok(sock) => sock,
        Err(e) => {
            println!("     Couldn't connect to data socket: {e:?}");
            return Err(e.into());
        }
    };

    let mut framed_data_socket = Framed::new(&mut data_socket, LengthDelimitedCodec::new());

    let al_registration_request = AlServiceRegistrationRequest {
        service_operation: ServiceOperation::Enable,
        service_type: ServiceType::EasyMeshAgent,
    };

    println!("1.1: Registering");
    let serialized = al_registration_request.serialize();
    match framed_control_socket
        .send(bytes::Bytes::from(serialized.clone()))
        .await
    {
        Ok(()) => {
            println!("     Send ok");
        }
        Err(e) => {
            println!("     Send error {e:?}");
            return Err(e.into());
        }
    };

    let reg_resp: AlServiceRegistrationResponse;

    println!("1.2: Waiting for registration response");
    let response = framed_control_socket.next().await;
    match response {
        Some(res) => match res {
            Ok(bytes) => {
                (_, reg_resp) = AlServiceRegistrationResponse::parse(bytes.as_ref()).unwrap();
                println!("     Got registration response: {reg_resp:?}");
            }
            Err(e) => {
                panic!("     Got parse error: {e:?}")
            }
        },
        None => {
            panic!("     Got none as response;")
        }
    }
    println!("1.3: Registration succeeded");

    let topology_db = topology_ui.then(|| {
        let topology_db =
            TopologyDatabase::get_instance(reg_resp.al_mac_address_local, interface_name);
        tokio::task::spawn(topology_db.clone().start_topology_cli());
        topology_db
    });

    loop {
        println!("2.0 Prepare and send multicast autoconfig search request");
        let sdu_autoconfig_search = prepare_payload_with_huge_tlv(&reg_resp, true);
        update_observed_topology_from_bytes(topology_db.as_ref(), &sdu_autoconfig_search).await;
        match framed_data_socket
            .send(Bytes::from(sdu_autoconfig_search.clone()))
            .await
        {
            Ok(_) => {
                println!("Successfully send SDU {sdu_autoconfig_search:?}");
            }
            Err(err) => {
                println!("Sending SDU FAILURE {err}");
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        // println!("2.1 Prepare and send autoconfig search request");
        // let sdu_autoconfig_search = prepare_autoconfig_search_request_sdu(&reg_resp, false);
        // match framed_data_socket.send(Bytes::from(sdu_autoconfig_search.clone())).await {
        //             Ok(_) => { println!("Successfully send SDU {sdu_autoconfig_search:?}"); },
        //             Err(err) => { println!("Sending SDU FAILURE {err}"); }
        // }
    }
    //Ok(())
}

async fn connect(
    cp: &str,
    dp: &str,
) -> anyhow::Result<(
    Option<Framed<UnixStream, LengthDelimitedCodec>>,
    Option<Framed<UnixStream, LengthDelimitedCodec>>,
)> {
    let control_socket: UnixStream = match UnixStream::connect(cp).await {
        Ok(stream) => stream,
        Err(e) => {
            println!("Couldn't connect to control socket: {e:?}");
            return Err(e.into());
        }
    };
    println!("Connected to control socket");

    let framed_control_socket = Framed::new(control_socket, LengthDelimitedCodec::new());

    let data_socket = match UnixStream::connect(dp).await {
        Ok(stream) => stream,
        Err(e) => {
            println!("Couldn't connect to data socket: {e:?}");
            return Err(e.into());
        }
    };
    let framed_data_socket = Framed::new(data_socket, LengthDelimitedCodec::new());

    println!("Connected to data socket");

    Ok((Some(framed_control_socket), Some(framed_data_socket)))
}

async fn connect_with_retry(
    cp: &str,
    dp: &str,
) -> (
    Framed<UnixStream, LengthDelimitedCodec>,
    Framed<UnixStream, LengthDelimitedCodec>,
) {
    loop {
        match connect(cp, dp).await {
            Ok((Some(control), Some(data))) => return (control, data),
            Ok(_) => {
                println!("Sockets not available. Retrying...");
            }
            Err(e) => {
                println!("Couldn't connect to AL-SAP sockets: {e:?}. Retrying...");
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
}

async fn register(
    framed_control_socket: &mut Framed<UnixStream, LengthDelimitedCodec>,
) -> anyhow::Result<AlServiceRegistrationResponse> {
    let al_registration_request = AlServiceRegistrationRequest {
        service_operation: ServiceOperation::Enable,
        service_type: ServiceType::EasyMeshAgent,
    };

    println!("Sending registration request...");
    let serialized = al_registration_request.serialize();

    framed_control_socket
        .send(bytes::Bytes::from(serialized.clone()))
        .await
        .map_err(|e| {
            println!("Send error: {e:?}");
            e
        })?;

    println!("Waiting for registration response...");
    match framed_control_socket.next().await {
        Some(Ok(bytes)) => {
            let (_, reg_resp) = AlServiceRegistrationResponse::parse(bytes.as_ref())
                .map_err(|e| anyhow::anyhow!("Parse error: {e:?}"))?;
            println!("Got registration response: {reg_resp:?}");
            println!("Registration succeeded");
            Ok(reg_resp)
        }
        Some(Err(e)) => Err(anyhow::anyhow!("Error receiving response: {e:?}")),
        None => Err(anyhow::anyhow!("No response received")),
    }
}

async fn send_short_data(
    framed_data_socket: &mut Framed<UnixStream, LengthDelimitedCodec>,
    reg_resp: AlServiceRegistrationResponse,
    topology_db: Option<&Arc<TopologyDatabase>>,
) -> anyhow::Result<Vec<u8>> {
    println!("Sending data");
    println!("Prepare and send multicast autoconfig search request");

    let sdu_short = prepare_payload_with_small_tlv(&reg_resp, false);
    update_observed_topology_from_bytes(topology_db, &sdu_short).await;
    match framed_data_socket
        .send(Bytes::from(sdu_short.clone()))
        .await
    {
        Ok(_) => {
            println!("Successfully sent SDU");
        }
        Err(err) => {
            println!("Sending SDU FAILURE {err}");
        }
    }

    Ok(sdu_short)
}

async fn send_huge_data(
    framed_data_socket: &mut Framed<UnixStream, LengthDelimitedCodec>,
    reg_resp: AlServiceRegistrationResponse,
    topology_db: Option<&Arc<TopologyDatabase>>,
) -> anyhow::Result<Vec<u8>> {
    println!("Sending data");
    println!("Prepare and send multicast autoconfig search request");
    let sdu_autoconfig_search = prepare_payload_with_huge_tlv(&reg_resp, true);
    update_observed_topology_from_bytes(topology_db, &sdu_autoconfig_search).await;
    match framed_data_socket
        .send(Bytes::from(sdu_autoconfig_search.clone()))
        .await
    {
        Ok(_) => {
            println!("Successfully send SDU");
        }
        Err(err) => {
            println!("Sending SDU FAILURE {err}");
        }
    }

    Ok(sdu_autoconfig_search)
}

async fn send_ap_autoconfig_request(
    framed_data_socket: &mut Framed<UnixStream, LengthDelimitedCodec>,
    reg_resp: &AlServiceRegistrationResponse,
    message_id: u16,
    topology_db: Option<&Arc<TopologyDatabase>>,
) -> anyhow::Result<Vec<u8>> {
    println!("Sending AP autoconfig request");
    let sdu_ap_autoconfig_request = prepare_ap_autoconfig_request_sdu(reg_resp, message_id);
    update_observed_topology_from_bytes(topology_db, &sdu_ap_autoconfig_request).await;

    framed_data_socket
        .send(Bytes::from(sdu_ap_autoconfig_request.clone()))
        .await
        .map_err(|err| anyhow::anyhow!("Sending AP autoconfig request failed: {err}"))?;

    println!("Successfully sent AP autoconfig request");
    Ok(sdu_ap_autoconfig_request)
}

async fn read_data(
    framed_data_socket: &mut Framed<UnixStream, LengthDelimitedCodec>,
    topology_db: Option<&Arc<TopologyDatabase>>,
) -> anyhow::Result<SDU> {
    println!("Waiting for any data");

    let mut assembled_payload = Vec::new();
    let mut fragment_id_expected = 0;
    let mut message: Option<SDU> = None;

    loop {
        tracing::trace!("LOOP");
        let response_data = framed_data_socket.next().await;
        match response_data {
            Some(res) => {
                match res {
                    Ok(bytes) => {
                        tracing::trace!("Got some bytes: [{}] <{:?}>", bytes.len(), bytes);
                        match SDU::parse(&bytes) {
                            Ok(tuple) => {
                                tracing::trace!("Got SDU");
                                let fragment = tuple.1;
                                if fragment.is_fragment == 0 && fragment.is_last_fragment == 1 {
                                    // Single complete message
                                    let complete_sdu = fragment.clone();

                                    tracing::trace!(
                                        "Got complete SDU [{}] {complete_sdu:?}",
                                        complete_sdu.payload.len()
                                    );
                                    update_observed_topology(topology_db, &complete_sdu).await;
                                    return Ok(complete_sdu);
                                }

                                if fragment.fragment_id != fragment_id_expected {
                                    tracing::error!(
                                        "Fragment out of order expected {}, got {}",
                                        fragment_id_expected,
                                        fragment.fragment_id
                                    );
                                    continue;
                                }

                                if fragment_id_expected == 0 {
                                    message = Some(SDU {
                                        source_al_mac_address: fragment.source_al_mac_address,
                                        destination_al_mac_address: fragment
                                            .destination_al_mac_address,
                                        is_fragment: 0,
                                        is_last_fragment: 0,
                                        fragment_id: 0,
                                        payload: Vec::new(),
                                    });
                                }

                                assembled_payload.extend(&fragment.payload);
                                if fragment.is_last_fragment == 1
                                    && let Some(mut final_message) = message.clone()
                                {
                                    final_message.payload = assembled_payload.clone();
                                    tracing::info!(
                                        "Got reassembled SDU [{:?}] {final_message:?}",
                                        final_message.payload.len()
                                    );
                                    update_observed_topology(topology_db, &final_message).await;
                                    return Ok(final_message);
                                }
                                fragment_id_expected += 1;
                            }
                            Err(e) => {
                                tracing::error!("Failed to parse SDU {e:?}");
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        println!("     Got parse error: {e:?}");
                    }
                }
            }
            None => {
                println!("     Got none as response. Exit.");
                exit(1);
            }
        }
    }
}

async fn read_ap_autoconfig_response(
    framed_data_socket: &mut Framed<UnixStream, LengthDelimitedCodec>,
    topology_db: Option<&Arc<TopologyDatabase>>,
) -> anyhow::Result<()> {
    let sdu = read_data(framed_data_socket, topology_db).await?;

    if is_ap_autoconfig_response(&sdu) {
        println!("Received AP autoconfig response");
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Received data, but it was not an AP autoconfig response"
        ))
    }
}

// Read complete SDU with CMDU and TLVs and compare CMDU payload
async fn read_and_compare_data(
    framed_data_socket: &mut Framed<UnixStream, LengthDelimitedCodec>,
    data_to_compare: &Vec<u8>,
    topology_db: Option<&Arc<TopologyDatabase>>,
) -> anyhow::Result<()> {
    let sdu_wrapped = read_data(framed_data_socket, topology_db).await;
    match sdu_wrapped {
        Ok(sdu) => {
            let sdu_payload_sent = SDU::parse(data_to_compare.as_slice()).unwrap().1.payload;
            let cmdu_payload_sent = CMDU::parse(&sdu_payload_sent.clone()).unwrap().1.payload;

            // cmdu: header with cmdu payload
            let sdu_payload_received = sdu.payload;
            let cmdu_payload_received = CMDU::parse(&sdu_payload_received.clone())
                .unwrap()
                .1
                .payload;

            println!(
                "Compare lengths: sent SDU: {} and received SDU: {}",
                sdu_payload_sent.len(),
                sdu_payload_received.len()
            );
            assert_eq!(cmdu_payload_sent.len(), cmdu_payload_received.len());

            // compare only CMDU payloads from SDU sent by us and returned (echoed) by receiver
            assert_eq!(cmdu_payload_sent, cmdu_payload_received);
            println!("Both CMD payloads verified successfully (both identical)");
            Ok(())
        }
        Err(err) => {
            println!("Got error");
            Err(err)
        }
    }
}

async fn close_control_connection(
    framed_control_socket: &mut Framed<UnixStream, LengthDelimitedCodec>,
) {
    let _ = framed_control_socket.flush().await;
    let _ = framed_control_socket.close().await;
}

async fn close_data_connection(framed_data_socket: &mut Framed<UnixStream, LengthDelimitedCodec>) {
    let _close = framed_data_socket.flush().await;
    let _close = framed_data_socket.close().await;
}

// Common case: Connect -> Register -> Send data
async fn test2_common_without_breaking_connection(
    sap_control_path: &str,
    sap_data_path: &str,
    interface_name: &str,
    topology_ui: bool,
) -> anyhow::Result<()> {
    let mut framed_control_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut framed_data_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut reg_resp: Option<AlServiceRegistrationResponse> = None;
    let mut topology_db: Option<Arc<TopologyDatabase>> = None;

    enum State {
        Connect,
        Register,
        SendData,
    }

    let mut state = State::Connect;

    println!("Starting test2");

    loop {
        match state {
            State::Connect => match connect(sap_control_path, sap_data_path).await {
                Ok((control, data)) => {
                    framed_control_socket = control;
                    framed_data_socket = data;
                    state = State::Register;
                    println!("Transition to Register");
                }
                Err(e) => {
                    println!("Failed to establish connection: {e:?}");
                    println!("Trying to re-connect");
                    sleep(Duration::from_millis(1000)).await;
                }
            },

            State::Register => {
                match framed_control_socket {
                    Some(ref mut control_socket) => match register(control_socket).await {
                        Ok(rr) => {
                            state = State::SendData;
                            println!(
                                "Transition to SendData with registration response: {:?}",
                                rr
                            );
                            if topology_ui && topology_db.is_none() {
                                let db = TopologyDatabase::get_instance(
                                    rr.al_mac_address_local,
                                    interface_name,
                                );
                                tokio::task::spawn(db.clone().start_topology_cli());
                                topology_db = Some(db);
                            }
                            reg_resp = Some(rr);
                        }
                        Err(e) => {
                            println!("Registration failed: {e:?}");
                            println!("Trying to re-register");
                        }
                    },
                    None => println!("Framed_control_socket not initialized"),
                };
            }

            State::SendData => {
                if let Some(mut data_socket) = framed_data_socket.take() {
                    if let Err(e) = send_short_data(
                        &mut data_socket,
                        reg_resp.clone().unwrap(),
                        topology_db.as_ref(),
                    )
                    .await
                    {
                        println!("Sending failed: {e:?}");
                        return Err(e);
                    }
                    println!("Test2 ended");
                    break;
                } else {
                    println!("Data socket not available");
                    sleep(Duration::from_millis(1000)).await;
                }
            }
        }
    }

    println!("Exit from test2\n");

    Ok(())
}

// Breaking connection case: Connect -> Register -> Break connection -> Re-connect -> Re-register -> Send data
async fn test3_breaking_connection(
    sap_control_path: &str,
    sap_data_path: &str,
    interface_name: &str,
    topology_ui: bool,
) -> anyhow::Result<()> {
    let mut framed_control_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut framed_data_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut reg_resp: Option<AlServiceRegistrationResponse> = None;
    let mut topology_db: Option<Arc<TopologyDatabase>> = None;

    enum State {
        Connect,
        Register,
        BreakConnection,
        ReConnect,
        ReRegister,
        SendData,
    }

    let mut state = State::Connect;

    println!("Starting test3");

    loop {
        match state {
            State::Connect => match connect(sap_control_path, sap_data_path).await {
                Ok((control, data)) => {
                    framed_control_socket = control;
                    framed_data_socket = data;
                    state = State::Register;
                    println!("Transition to Register");
                }
                Err(e) => {
                    println!("Failed to establish connection: {e:?}");
                    println!("Trying to re-connect");
                    sleep(Duration::from_millis(1000)).await;
                }
            },

            State::Register => {
                match framed_control_socket {
                    Some(ref mut control_socket) => match register(control_socket).await {
                        Ok(_) => {
                            state = State::BreakConnection;
                            println!("Transition to BreakConnection");
                        }
                        Err(e) => {
                            println!("Registration failed: {e:?}");
                            println!("Trying to re-register");
                        }
                    },
                    None => println!("Framed_control_socket not initialized"),
                };
            }

            State::BreakConnection => {
                match framed_control_socket {
                    Some(ref mut control_socket) => {
                        close_control_connection(control_socket).await;
                    }
                    None => println!("Framed_control_socket not initialized"),
                };
                match framed_data_socket {
                    Some(ref mut data_socket) => {
                        close_data_connection(data_socket).await;
                    }
                    None => println!("Framed_data_socket not initialized"),
                };
                state = State::ReConnect;
                println!("Transition to ReConnect");
            }

            State::ReConnect => match connect(sap_control_path, sap_data_path).await {
                Ok((control, data)) => {
                    framed_control_socket = control;
                    framed_data_socket = data;
                    state = State::ReRegister;
                    println!("Transition to ReRegister");
                }
                Err(e) => {
                    println!("Failed to establish connection: {e:?}");
                    println!("Trying to re-connect");
                    sleep(Duration::from_millis(1000)).await;
                }
            },

            State::ReRegister => {
                match framed_control_socket {
                    Some(ref mut control_socket) => match register(control_socket).await {
                        Ok(rr) => {
                            state = State::SendData;
                            println!(
                                "Transition to SendData with registration response: {:?}",
                                rr
                            );
                            if topology_ui && topology_db.is_none() {
                                let db = TopologyDatabase::get_instance(
                                    rr.al_mac_address_local,
                                    interface_name,
                                );
                                tokio::task::spawn(db.clone().start_topology_cli());
                                topology_db = Some(db);
                            }
                            reg_resp = Some(rr);
                        }
                        Err(e) => {
                            println!("Registration failed: {e:?}");
                            println!("Trying to re-register");
                        }
                    },
                    None => println!("Framed_control_socket not initialized"),
                };
            }

            State::SendData => {
                if let Some(mut data_socket) = framed_data_socket.take() {
                    if let Err(e) = send_huge_data(
                        &mut data_socket,
                        reg_resp.clone().unwrap(),
                        topology_db.as_ref(),
                    )
                    .await
                    {
                        println!("Sending failed: {e:?}");
                        return Err(e);
                    }
                    println!("Test3 ended");
                    break;
                } else {
                    println!("Data socket not available");
                    sleep(Duration::from_millis(1000)).await;
                }
            }
        }
    }
    println!("Exit from test3\n");

    Ok(())
}

// Breaking connection case: Connect -> Register -> Break connection -> Re-connect -> Re-register -> Send data -> Receive data -> Compare data
async fn test4_break_connection_and_receive(
    sap_control_path: &str,
    sap_data_path: &str,
    interface_name: &str,
    topology_ui: bool,
    read_timeout: u8,
    connect_timeout: u8,
) -> anyhow::Result<()> {
    let mut framed_control_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut framed_data_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut reg_resp: Option<AlServiceRegistrationResponse> = None;
    let mut topology_db: Option<Arc<TopologyDatabase>> = None;

    enum State {
        Connect,
        Register,
        BreakConnection,
        ReConnect,
        ReRegister,
        SendData,
        ReceiveAndCompareData,
    }

    let mut state = State::Connect;
    let mut try_no: u8 = 1;

    println!("Starting test4");
    let mut data_for_verification: Vec<u8> = Vec::new();

    loop {
        match state {
            State::Connect => match connect(sap_control_path, sap_data_path).await {
                Ok((control, data)) => {
                    framed_control_socket = control;
                    framed_data_socket = data;
                    state = State::Register;
                    try_no = 1;
                    println!("Transition to Register");
                }
                Err(e) => {
                    println!("Failed to establish connection: {e:?}");
                    if try_no < connect_timeout {
                        println!("Trying to re-connect (try: {try_no}/{connect_timeout})");
                        try_no += 1;
                        sleep(Duration::from_millis(100)).await;
                    } else {
                        println!("Trying to connect failed after {} tries", try_no);
                        return Err(anyhow::anyhow!(
                            "Trying to connect failed after {} tries",
                            try_no
                        ));
                    }
                }
            },

            State::Register => {
                match framed_control_socket {
                    Some(ref mut control_socket) => match register(control_socket).await {
                        Ok(_) => {
                            state = State::BreakConnection;
                            try_no = 1;
                            println!("Transition to BreakConnection");
                        }
                        Err(e) => {
                            println!("Registration failed: {e:?}");
                            println!("Trying to re-register");
                            if try_no < connect_timeout {
                                println!("Trying to register (try: {try_no}/{connect_timeout})");
                                try_no += 1;
                                sleep(Duration::from_millis(100)).await;
                            } else {
                                println!("Trying to register failed after {} tries", try_no);
                                return Err(anyhow::anyhow!(
                                    "Trying to register failed after {} tries",
                                    try_no
                                ));
                            }
                        }
                    },
                    None => println!("Framed_control_socket not initialized"),
                };
            }

            State::BreakConnection => {
                match framed_control_socket {
                    Some(ref mut control_socket) => {
                        close_control_connection(control_socket).await;
                    }
                    None => println!("Framed_control_socket not initialized"),
                };
                match framed_data_socket {
                    Some(ref mut data_socket) => {
                        close_data_connection(data_socket).await;
                    }
                    None => println!("Framed_data_socket not initialized"),
                };
                state = State::ReConnect;
                println!("Transition to ReConnect");
            }

            State::ReConnect => match connect(sap_control_path, sap_data_path).await {
                Ok((control, data)) => {
                    framed_control_socket = control;
                    framed_data_socket = data;
                    state = State::ReRegister;
                    try_no = 1;
                    println!("Transition to ReRegister");
                }
                Err(e) => {
                    println!("Failed to establish connection: {e:?}");
                    if try_no < connect_timeout {
                        println!("Trying to re-connect (try: {try_no}/{connect_timeout})");
                        try_no += 1;
                        sleep(Duration::from_millis(100)).await;
                    } else {
                        println!("Trying to re-connect failed after {} tries", try_no);
                        return Err(anyhow::anyhow!(
                            "Trying to re-connect failed after {} tries",
                            try_no
                        ));
                    }
                }
            },

            State::ReRegister => {
                match framed_control_socket {
                    Some(ref mut control_socket) => match register(control_socket).await {
                        Ok(rr) => {
                            state = State::SendData;
                            try_no = 1;
                            println!(
                                "Transition to SendData with registration response: {:?}",
                                rr
                            );
                            if topology_ui && topology_db.is_none() {
                                let db = TopologyDatabase::get_instance(
                                    rr.al_mac_address_local,
                                    interface_name,
                                );
                                tokio::task::spawn(db.clone().start_topology_cli());
                                topology_db = Some(db);
                            }
                            reg_resp = Some(rr);
                        }
                        Err(e) => {
                            println!("Registration failed: {e:?}");
                            println!("Trying to re-register");
                            if try_no < connect_timeout {
                                println!("Trying to register (try: {try_no}/{connect_timeout})");
                                try_no += 1;
                                sleep(Duration::from_millis(100)).await;
                            } else {
                                println!("Trying to register failed after {} tries", try_no);
                                return Err(anyhow::anyhow!(
                                    "Trying to register failed after {} tries",
                                    try_no
                                ));
                            }
                        }
                    },
                    None => println!("Framed_control_socket not initialized"),
                };
            }

            State::SendData => {
                if let Some(ref mut data_socket) = framed_data_socket {
                    let res = send_huge_data(
                        data_socket,
                        reg_resp.clone().unwrap(),
                        topology_db.as_ref(),
                    )
                    .await;
                    match res {
                        Err(e) => {
                            println!("Sending failed: {e:?}");
                            return Err(anyhow::anyhow!("Sending failed: {e:?}"));
                        }
                        Ok(sdu_sent) => {
                            data_for_verification = sdu_sent;
                        }
                    }
                    try_no = 1;
                    state = State::ReceiveAndCompareData;
                    println!("Transition to ReceiveDataAndCompareData");
                } else if framed_data_socket.is_none() {
                    println!("Data socket not available");
                    sleep(Duration::from_millis(100)).await;
                    return Err(anyhow::anyhow!("Data socket not available"));
                }
            }

            State::ReceiveAndCompareData => {
                tokio::select! {
                    res = async {
                        if let Some(ref mut data_socket) = framed_data_socket {
                            let rd = read_and_compare_data(data_socket, &data_for_verification, topology_db.as_ref()).await;
                            match rd {
                                Ok(_) => {
                                    println!("read_and_compare_data: ok");
                                    Ok(())
                                }
                                Err(e) => {
                                    println!("read_and_compare_data: failed: {e:?}");
                                    Err(anyhow::anyhow!("read_and_compare_data: failed: {e:?}"))
                                }
                            }
                        } else {
                            Err(anyhow::anyhow!("Data socket not available"))
                        }
                    } => {
                        println!("Test finished with result: {res:?}");
                        return Ok(());
                    }

                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        if try_no < read_timeout {
                            println!("Trying to read any data (try: {try_no}/{read_timeout})");
                            try_no += 1;
                        } else {
                            return Err(anyhow::anyhow!("Couldn't read any data during {} tries", read_timeout));
                        }
                    }
                }
            }
        }
    }
}

async fn test5_ap_autoconfig_request_loop(
    sap_control_path: &str,
    sap_data_path: &str,
    interface_name: &str,
    topology_ui: bool,
) -> anyhow::Result<()> {
    println!("Starting test5");

    let (mut framed_control_socket, mut framed_data_socket) =
        connect_with_retry(sap_control_path, sap_data_path).await;

    let reg_resp = register(&mut framed_control_socket).await?;
    let topology_db = topology_ui.then(|| {
        let db = TopologyDatabase::get_instance(reg_resp.al_mac_address_local, interface_name);
        tokio::task::spawn(db.clone().start_topology_cli());
        db
    });

    let mut message_id = 1_u16;
    loop {
        send_ap_autoconfig_request(
            &mut framed_data_socket,
            &reg_resp,
            message_id,
            topology_db.as_ref(),
        )
        .await?;

        match timeout(
            Duration::from_secs(10),
            read_ap_autoconfig_response(&mut framed_data_socket, topology_db.as_ref()),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => println!("AP autoconfig response validation failed: {e:?}"),
            Err(_) => println!("Timed out waiting for AP autoconfig response"),
        }

        message_id = if message_id == u16::MAX {
            1
        } else {
            message_id + 1
        };
        sleep(Duration::from_secs(10)).await;
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None, name = "IEEE1905 functional tests suite")]
struct Args {
    /// Control socket path
    #[clap(short = 'c', long, default_value = "/tmp/al_control_socket")]
    control_path: String,

    /// Data socket path
    #[clap(short = 'd', long, default_value = "/tmp/al_data_socket")]
    data_path: String,

    /// Test number to run
    #[clap(short = 't', long, default_value_t = 4)]
    test_num: u8,

    /// Connect/Register timeout in 0.1s units (10 = 1 second)
    #[clap(short = 'n', long, default_value_t = 100)]
    connect: u8,

    /// Read/Send timeout in 0.1s units (10 = 1 second)
    #[clap(short = 'r', long, default_value_t = 100)]
    read: u8,
}

pub async fn run_with_config(
    sap_control_path: &str,
    sap_data_path: &str,
    interface_name: &str,
    topology_ui: bool,
    test: u8,
    read: u8,
    connect: u8,
) -> anyhow::Result<()> {
    let mut t: anyhow::Result<()> = Ok(());

    // Not modularized test1
    if test == 1 {
        t = test1(sap_control_path, sap_data_path, interface_name, topology_ui).await;
    }

    // Modularized tests
    if test == 2 {
        t = test2_common_without_breaking_connection(
            sap_control_path,
            sap_data_path,
            interface_name,
            topology_ui,
        )
        .await;
    }

    if test == 3 {
        t = test3_breaking_connection(sap_control_path, sap_data_path, interface_name, topology_ui)
            .await;
    }

    if test == 4 {
        t = test4_break_connection_and_receive(
            sap_control_path,
            sap_data_path,
            interface_name,
            topology_ui,
            read,
            connect,
        )
        .await;
    }

    if test == 5 {
        t = test5_ap_autoconfig_request_loop(
            sap_control_path,
            sap_data_path,
            interface_name,
            topology_ui,
        )
        .await;
    }

    return t;
}

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    let control_path = args.control_path;
    let data_path = args.data_path;
    run_with_config(
        &control_path,
        &data_path,
        "eth0",
        false,
        args.test_num,
        args.read,
        args.connect,
    )
    .await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}
