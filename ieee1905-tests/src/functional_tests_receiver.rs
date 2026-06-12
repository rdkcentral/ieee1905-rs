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
use futures::{SinkExt, StreamExt};
use ieee1905::cmdu::CMDU;
use ieee1905::cmdu_codec::{
    AlMacAddress, CMDUType, IEEE1905TLVType, MessageVersion, SearchedRole, SupportedRole,
    SupportedService, SupportedServiceType,
};
use ieee1905::registration_codec::{
    AlServiceRegistrationRequest, AlServiceRegistrationResponse, ServiceOperation, ServiceType,
};
use ieee1905::sdu_codec::SDU;
use ieee1905::tlv_cmdu_codec::TLVTrait;
use ieee1905::topology_manager::{Ieee1905DeviceData, TopologyDatabase, UpdateType};
use std::process::exit;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::time::{Duration, sleep};
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

fn build_tlv(tlv_type: IEEE1905TLVType, value: Option<Vec<u8>>) -> ieee1905::cmdu::TLV {
    ieee1905::cmdu::TLV {
        tlv_type: tlv_type.to_u8(),
        tlv_length: value.as_ref().map_or(0, Vec::len) as u16,
        tlv_value: value,
    }
}

fn build_ap_autoconfig_response(
    requester_al_mac: pnet::datalink::MacAddr,
    request_cmdu: &CMDU,
    local_al_mac: pnet::datalink::MacAddr,
) -> SDU {
    tracing::debug!(
        source = %local_al_mac,
        destination = %requester_al_mac,
        message_id = request_cmdu.message_id,
        "CONTROLLER: building AP autoconfig response"
    );

    let mut payload = Vec::new();
    payload.extend(
        build_tlv(
            IEEE1905TLVType::SupportedRole,
            Some(SupportedRole { role: 0x00 }.serialize()),
        )
        .serialize(),
    );
    payload.extend(
        build_tlv(
            IEEE1905TLVType::SupportedService,
            Some(
                SupportedService {
                    services: vec![SupportedServiceType::Controller],
                }
                .serialize(),
            ),
        )
        .serialize(),
    );
    payload.extend(build_tlv(IEEE1905TLVType::EndOfMessage, None).serialize());

    let response_cmdu = CMDU {
        message_version: MessageVersion::Version2013.to_u8(),
        reserved: 0,
        message_type: CMDUType::ApAutoConfigResponse.to_u16(),
        message_id: request_cmdu.message_id,
        fragment: 0,
        flags: 0x80,
        payload,
    };

    SDU {
        source_al_mac_address: local_al_mac,
        destination_al_mac_address: requester_al_mac,
        is_fragment: 0,
        is_last_fragment: 1,
        fragment_id: 0,
        payload: response_cmdu.serialize(),
    }
}

fn validate_ap_autoconfig_search(cmdu: &CMDU) -> Result<pnet::datalink::MacAddr, &'static str> {
    if cmdu.message_type != CMDUType::ApAutoConfigSearch.to_u16() {
        return Err("unexpected CMDU message type");
    }

    let tlvs = cmdu.get_tlvs().map_err(|_| "failed to parse TLVs")?;

    let Some(al_mac) = AlMacAddress::find(&tlvs) else {
        return Err("missing or invalid AlMacAddress TLV");
    };
    let requester_al_mac = al_mac.al_mac_address;

    let Some(searched_role) = SearchedRole::find(&tlvs) else {
        return Err("missing or invalid SearchedRole TLV");
    };
    if searched_role.role != 0x00 {
        return Err("SearchedRole TLV is not registrar");
    }

    let Some(supported_service) = SupportedService::find(&tlvs) else {
        return Err("missing or invalid SupportedService TLV");
    };
    if !supported_service
        .services
        .iter()
        .any(|service| matches!(service, SupportedServiceType::Agent))
    {
        return Err("SupportedService TLV does not contain Agent");
    }

    Ok(requester_al_mac)
}

async fn connect_unix_socket_with_retry(path: &str, socket_name: &str) -> UnixStream {
    loop {
        match UnixStream::connect(path).await {
            Ok(unix_stream) => {
                println!("Connected to {socket_name} socket");
                return unix_stream;
            }
            Err(e) => {
                println!("Couldn't connect to {socket_name} socket: {e:?}. Retrying...");
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

// Send response to transmitter containing complete SDU: (SDU + CMDU + TLVs)
// Only the TLV chain is a 1-to-1 copy without any modifications as SDU and CMDU headers
// need to be changed for proper SDU delivery
async fn send_echoed_packet(
    socket: &mut Framed<&mut UnixStream, LengthDelimitedCodec>,
    bytes: Vec<u8>,
    topology_db: Option<&Arc<TopologyDatabase>>,
    local_al_mac: pnet::datalink::MacAddr,
) {
    let sdu = SDU::parse(bytes.as_slice());
    match sdu {
        Ok(res) => {
            update_observed_topology(topology_db, &res.1).await;
            let source_mac = res.1.source_al_mac_address;
            let destination_mac = res.1.destination_al_mac_address;
            let payload = res.1.payload;

            let cmdu_with_payload = CMDU::parse(&payload[..]);
            match cmdu_with_payload {
                Ok(res) => {
                    let cmdu = res.1;
                    tracing::debug!(
                        source = %source_mac,
                        destination = %destination_mac,
                        message_type = cmdu.message_type,
                        message_id = cmdu.message_id,
                        payload_len = cmdu.payload.len(),
                        "CONTROLLER: received CMDU"
                    );

                    if cmdu.message_type == CMDUType::ApAutoConfigSearch.to_u16() {
                        let requester_al_mac = match validate_ap_autoconfig_search(&cmdu) {
                            Ok(requester_al_mac) => requester_al_mac,
                            Err(reason) => {
                                tracing::warn!(
                                    source = %source_mac,
                                    destination = %destination_mac,
                                    message_id = cmdu.message_id,
                                    reason,
                                    "CONTROLLER: ignored malformed AP autoconfig search"
                                );
                                println!(
                                    "CONTROLLER: ignored malformed AP autoconfig search: {reason}"
                                );
                                return;
                            }
                        };

                        tracing::info!(
                            source = %source_mac,
                            destination = %destination_mac,
                            requester_al_mac = %requester_al_mac,
                            message_id = cmdu.message_id,
                            "CONTROLLER: AP autoconfig search validation succeeded"
                        );
                        println!("CONTROLLER: received AP autoconfig search");
                        let sdu =
                            build_ap_autoconfig_response(requester_al_mac, &cmdu, local_al_mac);
                        let s = socket.send(bytes::Bytes::from(sdu.serialize())).await;
                        match s {
                            Ok(()) => {
                                tracing::info!(
                                    source = %local_al_mac,
                                    destination = %requester_al_mac,
                                    message_id = cmdu.message_id,
                                    "CONTROLLER: sent AP autoconfig response"
                                );
                                println!("CONTROLLER: sent AP autoconfig response");
                            }
                            Err(e) => {
                                tracing::error!(
                                    source = %local_al_mac,
                                    destination = %requester_al_mac,
                                    message_id = cmdu.message_id,
                                    error = ?e,
                                    "CONTROLLER: failed to send AP autoconfig response"
                                );
                                println!("CONTROLLER: failed to send AP autoconfig response: {e:?}")
                            }
                        }
                        return;
                    }

                    tracing::debug!(
                        source = %source_mac,
                        destination = %destination_mac,
                        message_type = cmdu.message_type,
                        message_id = cmdu.message_id,
                        "CONTROLLER: ignored non AP autoconfig CMDU"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        source = %source_mac,
                        destination = %destination_mac,
                        error = ?e,
                        "CONTROLLER: ignored SDU with unparseable CMDU"
                    );
                }
            }
        }
        Err(e) => {
            println!("Got parse error: {:?}", e);
        }
    }
}

pub async fn run_with_config(
    sap_control_path: &str,
    sap_data_path: &str,
    interface_name: &str,
    topology_ui: bool,
    service_type: ServiceType,
) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt_layer = fmt::layer().with_target(false).with_level(true);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();

    println!("Starting functional tests: receiver side.");

    let control_socket = connect_unix_socket_with_retry(sap_control_path, "control").await;

    let mut framed_control_socket: Framed<UnixStream, LengthDelimitedCodec> =
        Framed::new(control_socket, LengthDelimitedCodec::new());

    let mut data_socket = connect_unix_socket_with_retry(sap_data_path, "data").await;

    let mut framed_data_socket = Framed::new(&mut data_socket, LengthDelimitedCodec::new());

    let al_registration_request = AlServiceRegistrationRequest {
        service_operation: ServiceOperation::Enable,
        service_type,
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

    println!("2.1: Waiting for any data from unix stream socket");
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
                        tracing::trace!("Expecting id {:?}", fragment_id_expected);
                        match SDU::parse(&bytes) {
                            Ok(tuple) => {
                                tracing::trace!(
                                    "Bytes parsed to SDU. Left bytes {:?}",
                                    tuple.0.len()
                                );
                                let fragment = tuple.1;
                                if fragment.is_fragment == 0 && fragment.is_last_fragment == 1 {
                                    // Single complete message
                                    let complete_sdu = fragment.clone();

                                    tracing::debug!("Sending single message");
                                    send_echoed_packet(
                                        &mut framed_data_socket,
                                        complete_sdu.serialize(),
                                        topology_db.as_ref(),
                                        reg_resp.al_mac_address_local,
                                    )
                                    .await;
                                    continue;
                                }

                                if fragment.fragment_id != fragment_id_expected {
                                    tracing::error!(
                                        "Fragment out of order expected {}, got {}",
                                        fragment_id_expected,
                                        fragment.fragment_id
                                    );
                                    panic!("Fragment out of order");
                                } else {
                                    tracing::trace!("Fragment id match!");
                                }

                                if fragment_id_expected == 0 {
                                    tracing::trace!("Got first part of SDU");
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
                                if fragment.is_last_fragment == 1 && message.clone().is_some() {
                                    let mut final_message = message.clone().unwrap();
                                    final_message.payload = assembled_payload.clone();
                                    tracing::info!(
                                        "Got reassembled SDU payload_len={}",
                                        final_message.payload.len()
                                    );
                                    fragment_id_expected = 0;
                                    assembled_payload.clear();
                                    send_echoed_packet(
                                        &mut framed_data_socket,
                                        final_message.serialize(),
                                        topology_db.as_ref(),
                                        reg_resp.al_mac_address_local,
                                    )
                                    .await;
                                    continue;
                                }
                                tracing::trace!("Increasing expected ID");
                                fragment_id_expected += 1;
                            }
                            Err(e) => {
                                tracing::error!("Failed to parse SDU {e:?}");
                                panic!("Failed to parse SDU");
                            }
                        }
                    }
                    Err(e) => {
                        println!("Got parse error: {e:?}");
                    }
                }
            }
            None => {
                println!("Got none as response");
                exit(1);
            }
        }
    }
}

pub async fn run() -> anyhow::Result<()> {
    run_with_config(
        "/tmp/al_control_socket",
        "/tmp/al_data_socket",
        "eth0",
        false,
        ServiceType::EasyMeshAgent,
    )
    .await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}
