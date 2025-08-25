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
use eyre::Result;
use futures::{SinkExt, StreamExt};
use ieee1905::cmdu_codec::*;
use ieee1905::registration_codec::{
    AlServiceRegistrationRequest, AlServiceRegistrationResponse, ServiceOperation, ServiceType,
};
use ieee1905::sdu_codec::SDU;
use pnet::datalink::*;
use tokio::net::UnixStream;
use tokio::time::{sleep, Duration};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use std::process::exit;
use clap::Parser;

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

#[cfg(not(feature = "size_based_fragmentation"))]
fn prepare_autoconfig_search_request_sdu(
    r: &AlServiceRegistrationResponse,
    multicast: bool,
) -> Vec<u8> {
    // Here is whole SDU with autoconfig request taken from onewifi_em_agent
    let src_mac_addr = r.al_mac_address_local;
    let mut dest_mac_addr: MacAddr = MacAddr::new(0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02);
    if multicast {
        dest_mac_addr = MacAddr::new(0x01, 0x80, 0xc2, 0x00, 0x00, 0x13);
    }
    let sdu_bytes: Vec<u8> = vec![
        src_mac_addr.0,     // SDU source_al_mac_address
        src_mac_addr.1,
        src_mac_addr.2,
        src_mac_addr.3,
        src_mac_addr.4,
        src_mac_addr.5,
        dest_mac_addr.0,    // SDU destination_al_mac_address
        dest_mac_addr.1,
        dest_mac_addr.2,
        dest_mac_addr.3,
        dest_mac_addr.4,
        dest_mac_addr.5,
        0x00,                // SDU is_fragment
        0x01,                // SDU is_last_fragment
        0x00,                // SDU fragment_id

        // Start of CMDU
        0x00,               // CMDU message_version
        0x00,               // CMDU reserved
        0x00, 0x07,         // CMDU message_type
        0x0a, 0x00,         // CMDU message_id
        0x00,               // CMDU fragment
        0xc0,               // CMDU flags

        // Start of TLVs
        // TLV 1: 6-9 AL MAC address type TLV
        0x01,               // TLV type 1: 6-9 AL MAC address
        0x00, 0x06,         // TLV length
        src_mac_addr.0,     // AL MAC address
        src_mac_addr.1,
        src_mac_addr.2,
        src_mac_addr.3,
        src_mac_addr.4,
        src_mac_addr.5,

        // TLV 2: 6-22—SearchedRole TLV
        0x0d,               // TLV type: 6-22 SearchedRole
        0x00, 0x01,         // TLV length
        0x00,               // TLV payload

        // TLV 3: 6-23 AutoconfigFreqBand TLV
        0x0e,               // TLV type 14: 6-23 AutoconfigFreqBand
        0x00, 0x01,         // TLV length
        0x00,               // TLV 6-23 AutoconfigFreqBand

         // TLV 4: supported service 17.2.1
        0x80,
        0x00, 0x02,
        0x01, 0x01,         // TLV supported service 17.2.1

        // TLV 5: searched service 17.2.2
        0x81,
        0x00, 0x02,         // TLV length
        0x01, 0x00,         // TLV searched service 17.2.2

        // TLV 6: One multiAP profile tlv 17.2.47
        0xb3,
        0x00, 0x01,         // TLV length
        0x03,               // TLV One multiAP profile tlv 17.2.47

        0x00,               // TLV 7 End of message
        0x00,
        0x00,
    ];
    tracing::trace!("SDU_BYTES: [{:?}] <{:?}>", sdu_bytes.len(), sdu_bytes);
    if let Ok((_, sdu)) = SDU::parse(sdu_bytes.as_slice()) {
        return sdu.serialize();
    }
    vec![]
}

#[cfg(not(feature = "size_based_fragmentation"))]
fn _prepare_test_packet_channel_selection_request(r: &AlServiceRegistrationResponse) -> Vec<u8> {
    let al_mac = r.al_mac_address_local;

    let payload: Vec<u8> = vec![
        // CMDU
        0x00,               // messsage version
        0x00,               // reserved
        0x00, 0x07,         // messsage type
        0x00, 0x00,         // messsage id
        0x00,               // fragment
        0x80,               // flags

        // CMDU payload
        0x8b, 0x00, 0x13, 0xd8, 0x3a, 0xdd, 0x5e, 0x8a, 0x11, 0x03, 0x51, 0x01, 0x06, 0xee, 0x73,
        0x01, 0x24, 0xee, 0x87, 0x01, 0x01, 0xee, 0x8d, 0x00, 0x07, 0xd8, 0x3a, 0xdd, 0x5e, 0x8a,
        0x11, 0x00, 0x01, 0x00, 0x06, 0x02, 0x42, 0xc0, 0xa8, 0x64,
        0x03, // our (transmitter/node2) al_mac address
        0x02, 0x00, 0x06, 0x02, 0x42, 0xc0, 0xa8, 0x64, 0x03, // our (transmitter/node2) mac address
        0x00, 0x00, 0x00,
    ];

    let res = CMDU::parse(&payload[..]);
    println!("After cmdu parse: {:?}", res);

    let sdu = SDU {
        source_al_mac_address: al_mac,
        destination_al_mac_address: MacAddr::new(0xee, 0x42, 0xc0, 0xa8, 0x64, 0x02),
        is_fragment: 0,
        is_last_fragment: 1,
        fragment_id: 0,
        payload: payload,
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
        src_mac_addr.0,     // SDU source_al_mac_address
        src_mac_addr.1,
        src_mac_addr.2,
        src_mac_addr.3,
        src_mac_addr.4,
        src_mac_addr.5,
        dest_mac_addr.0,    // SDU destination_al_mac_address
        dest_mac_addr.1,
        dest_mac_addr.2,
        dest_mac_addr.3,
        dest_mac_addr.4,
        dest_mac_addr.5,
        0x00,               // SDU is_fragment
        0x01,               // SDU is_last_fragment
        0x00,               // SDU fragment_id

        // Start of CMDU
        0x00,               // CMDU message_version
        0x00,               // CMDU reserved
        0x00, 0x04,         // CMDU message_type - 0x0004 Vendor sepcific message
        0x00, 0x01,         // CMDU message_id
        0x00,               // CMDU fragment
        0x80,               // CMDU flags

        // Start of TLVs
        // TLV 1: 6-9 AL MAC address type TLV
        0x01,               // TLV type 1: 6-9 AL MAC address
        0x00, 0x06,         // TLV length
        src_mac_addr.0,     // AL MAC address
        src_mac_addr.1,
        src_mac_addr.2,
        src_mac_addr.3,
        src_mac_addr.4,
        src_mac_addr.5,

        // TLV 2: type Vendor Specific
        0x0b,               // TLV type: Vendor Specific
        0x00, 0x50,         // TLV len: 80 bytes
        // TLV 2 vendor specific payload (zeroed placeholder)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // TLV 3: End of message
        0x00, 0x00, 0x00
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


#[cfg(feature = "size_based_fragmentation")]
fn prepare_payload_with_huge_tlv(r: &AlServiceRegistrationResponse, multicast: bool) -> Vec<u8> {
    // Here is whole SDU with autoconfig request taken from onewifi_em_agent_
    let src_mac_addr = r.al_mac_address_local;
    let mut dest_mac_addr: MacAddr = MacAddr::new(0xee, 0x42, 0xc0, 0xa8, 0x64, 0x02);
    if multicast {
        dest_mac_addr = MacAddr::new(0x01, 0x80, 0xc2, 0x00, 0x00, 0x13);
    }
    let sdu_bytes: Vec<u8> = vec![
        src_mac_addr.0,     // SDU source_al_mac_address
        src_mac_addr.1,
        src_mac_addr.2,
        src_mac_addr.3,
        src_mac_addr.4,
        src_mac_addr.5,
        dest_mac_addr.0,    // SDU destination_al_mac_address
        dest_mac_addr.1,
        dest_mac_addr.2,
        dest_mac_addr.3,
        dest_mac_addr.4,
        dest_mac_addr.5,
        0x00,               // SDU is_fragment
        0x01,               // SDU is_last_fragment
        0x00,               // SDU fragment_id

        // Start of CMDU
        0x00,               // CMDU message_version
        0x00,               // CMDU reserved
        0x00, 0x04,         // CMDU message_type: 4 - Vendor specific
        0x0a, 0x00,         // CMDU message_id
        0x00,               // CMDU fragment
        0x00,               // CMDU flags

        // Start of TLVs
        // TLV 1: 6-9 AL MAC address type TLV
        0x01,               // TLV type 1: 6-9 AL MAC address
        0x00, 0x06,         // TLV length
        src_mac_addr.0,     // AL MAC address
        src_mac_addr.1,
        src_mac_addr.2,
        src_mac_addr.3,
        src_mac_addr.4,
        src_mac_addr.5,

        // TLV 2: 6-22 SearchedRole TLV
        0x0d,               // TLV type: 6-22 SearchedRole
        0x00, 0x01,         // TLV length
        0x00,               // TLV payload

        // TLV 3: 6-23 AutoconfigFreqBand TLV
        0x0e,               // TLV type 14: 6-23 AutoconfigFreqBand
        0x00, 0x01,         // TLV length
        0x00,               // TLV 6-23 AutoconfigFreqBand

        // TLV 4: supported service 17.2.1
        0x80,
        0x00, 0x02,         // TLV length
        0x01, 0x01,         // TLV supported service 17.2.1

        // TLV 5: searched service 17.2.2
        0x81,
        0x00, 0x02,         // TLV length
        0x01, 0x00,         // TLV searched service 17.2.2

        // TLV 6: One multiAP profile tlv 17.2.47
        0xb3,
        0x00, 0x01,         // TLV length
        0x03,               // TLV 6 One multiAP profile tlv 17.2.47

        // TLV 7: type Vendor Specific
        0x0b,               // TLV type: Vendor Specific
        0x05, 0xdc,         // TLV len: 1500 bytes
        // TLV 7 vendor specific payload (zeroed placeholder: 1500 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // End of zeroed 1500 bytes block

        // TLV 8: End of message
        0x00,       // TLV type 0: 6-6 End of message type
        0x00, 0x00,
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


async fn test1() -> Result<()> {
    // Modify this filter for your tracing during run time
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace")); //add 'tokio=trace' to debug the runtime

    // To show logs in stdout
    let fmt_layer = fmt::layer().with_target(true).with_level(true);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();

    println!("Starting test1");

    let sap_control_path = "/tmp/al_control_socket";
    let sap_data_path = "/tmp/al_data_socket";

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

    loop {
        println!("2.0 Prepare and send multicast autoconfig search request");
        #[cfg(feature = "size_based_fragmentation")]
        let sdu_autoconfig_search = prepare_payload_with_huge_tlv(&reg_resp, true);
        #[cfg(not(feature = "size_based_fragmentation"))]
        let sdu_autoconfig_search = prepare_autoconfig_search_request_sdu(&reg_resp, true);
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
) -> anyhow::Result<Vec<u8>> {
    println!("Sending data");
    println!("Prepare and send multicast autoconfig search request");

    let sdu_short = prepare_payload_with_small_tlv(&reg_resp, false);
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
) -> anyhow::Result<Vec<u8>> {
    println!("Sending data");
    println!("Prepare and send multicast autoconfig search request");
    #[cfg(feature = "size_based_fragmentation")]
    let sdu_autoconfig_search = prepare_payload_with_huge_tlv(&reg_resp, true);
    #[cfg(not(feature = "size_based_fragmentation"))]
    let sdu_autoconfig_search = prepare_autoconfig_search_request_sdu(&reg_resp, true);
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

async fn read_data(framed_data_socket: &mut Framed<UnixStream, LengthDelimitedCodec>) -> Result<SDU> {
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

                                    tracing::trace!("Got complete SDU [{}] {complete_sdu:?}", complete_sdu.payload.len());
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
                                if fragment.is_last_fragment == 1 {
                                    if message.clone().is_some() {
                                        let mut final_message = message.clone().unwrap();
                                        final_message.payload = assembled_payload.clone();
                                        tracing::info!("Got reassembled SDU [{:?}] {final_message:?}", final_message.payload.len());
                                        return Ok(final_message);
                                    }
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

// Read complete SDU with CMDU and TLVs and compare CMDU payload
async fn read_and_compare_data(framed_data_socket: &mut Framed<UnixStream, LengthDelimitedCodec>, data_to_compare: &Vec<u8>) -> Result<()> {
    let sdu_wrapped = read_data(framed_data_socket).await;
    match sdu_wrapped {
        Ok(sdu) => {
            let sdu_payload_sent = SDU::parse(data_to_compare.as_slice()).unwrap().1.payload;
            let cmdu_payload_sent = CMDU::parse(&sdu_payload_sent.clone()).unwrap().1.payload;

            // cmdu: header with cmdu payload
            let sdu_payload_received = sdu.payload;
            let cmdu_payload_received = CMDU::parse(&sdu_payload_received.clone()).unwrap().1.payload;

            println!("Compare lengths: sent SDU: {} and received SDU: {}", sdu_payload_sent.len(), sdu_payload_received.len());
            assert_eq!(cmdu_payload_sent.len(), cmdu_payload_received.len());

            // compare only CMDU payloads from SDU sent by us and returned (echoed) by receiver
            assert_eq!(cmdu_payload_sent, cmdu_payload_received);
            println!("Both CMD payloads verified successfully (both identical)");
            Ok(())
        }
        Err(err) => {
            println!("Got error");
            Err(err.into())
        }
    }
}

async fn close_control_connection(
    framed_control_socket: &mut Framed<UnixStream, LengthDelimitedCodec>,
) {
    let _ = framed_control_socket.flush().await;
    let _ = framed_control_socket.close().await;
}

async fn close_data_connection(
    framed_data_socket: &mut Framed<UnixStream, LengthDelimitedCodec>,
) {
    let _close = framed_data_socket.flush().await;
    let _close = framed_data_socket.close().await;
}

// Common case: Connect -> Register -> Send data
async fn test2_common_without_breaking_connection() -> anyhow::Result<()> {
    let sap_control_path = "/tmp/al_control_socket";
    let sap_data_path = "/tmp/al_data_socket";

    let mut framed_control_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut framed_data_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut reg_resp: Option<AlServiceRegistrationResponse> = None;

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
                            println!("Transition to SendData with registration response: {:?}", rr);
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
                if let Some(mut
                data_socket) = framed_data_socket.take() {
                    if let Err(e) = send_short_data(&mut data_socket, reg_resp.clone().unwrap()).await {
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
async fn test3_breaking_connection(sap_control_path: &str, sap_data_path: &str) -> anyhow::Result<()> {
    let mut framed_control_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut framed_data_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut reg_resp: Option<AlServiceRegistrationResponse> = None;

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
                    if let Err(e) = send_huge_data(&mut data_socket, reg_resp.clone().unwrap()).await {
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
async fn test4_break_connection_and_receive(sap_control_path: &str, sap_data_path: &str, read_timeout: u8, connect_timeout: u8) -> anyhow::Result<()> {
    let mut framed_control_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut framed_data_socket: Option<Framed<UnixStream, LengthDelimitedCodec>> = None;
    let mut reg_resp: Option<AlServiceRegistrationResponse> = None;

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
    let mut test_finished: bool = false;
    let mut test_result: bool = false;

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
                        println!("Trying to re-connect failed after {} tries", try_no);
                        test_finished = true;
                        test_result = false;
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
                                test_finished = true;
                                test_result = false;
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
                        test_finished = true;
                        test_result = false;
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
                                test_finished = true;
                                test_result = false;
                            }
                        }
                    },
                    None => println!("Framed_control_socket not initialized"),
                };
            }

            State::SendData => {
                if let Some(ref mut data_socket) = framed_data_socket {
                    #[cfg(feature = "size_based_fragmentation")]
                    let res = send_huge_data(data_socket, reg_resp.clone().unwrap()).await;
                    #[cfg(not(feature = "size_based_fragmentation"))]
                    let res = send_short_data(data_socket, reg_resp.clone().unwrap()).await;
                    match res {
                        Err(e) => {
                            println!("Sending failed: {e:?}");
                            return Err(e);
                        }
                        Ok(sdu_sent) => {
                            data_for_verification = sdu_sent;
                        }
                    }
                    try_no = 1;
                    state = State::ReceiveAndCompareData;
                    println!("Transition to ReceiveDataAndCompareData");
                } else if let None = framed_data_socket.take() {
                    println!("Data socket not available");
                    sleep(Duration::from_millis(100)).await;
                    test_finished = true;
                    test_result = false;
                }
            }

            State::ReceiveAndCompareData => {
                tokio::select! {
                    res = async {
                        if let Some(ref mut data_socket) = framed_data_socket {
                            let rd = read_and_compare_data(data_socket, &data_for_verification).await;
                            match rd {
                                Ok(_) => {
                                    println!("read_and_compare_data: ok");
                                    return true;
                                }
                                Err(e) => {
                                    println!("read_and_compare_data: failed: {e:?}");
                                    return false;
                                }
                            }
                        } else {
                            return false;
                        }
                    } => {
                        println!("Test finished with result: {res:?}");
                        test_finished = true;
                        test_result = res;
                    }

                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        if try_no < read_timeout {
                            println!("Trying to read any data (try: {try_no}/{read_timeout})");
                            try_no += 1;
                        } else {
                            test_finished = true;
                            test_result = false;
                        }

                    }
                }
            }
        }

        if test_finished { break; };
    }
    println!("Exit from test4 with result: {test_result:?}\n");

    Ok(())
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let connect = args.connect.clone();
    let test = args.test_num.clone();
    let read = args.read.clone();
    let sap_control_path: &str = &args.control_path.clone()[..];
    let sap_data_path = &args.data_path.clone()[..];


    // Not modularized test1
    if test == 1 {
        let _t1 = test1().await;
    }

    // Run modularized tests
    if test == 2 {
        let _t2 = test2_common_without_breaking_connection().await;
    }

    if test == 3 {
        let _t3 = test3_breaking_connection(sap_control_path, sap_data_path).await;
    }

    if test == 4 {
        let _t4 = test4_break_connection_and_receive(sap_control_path, sap_data_path, read, connect).await;
    }

    return Ok(());
}
