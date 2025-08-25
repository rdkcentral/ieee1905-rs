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
use std::process::exit;
use eyre::Result;
use futures::{SinkExt, StreamExt};
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use ieee1905::sdu_codec::SDU;
use ieee1905::registration_codec::{
    AlServiceRegistrationRequest,
    AlServiceRegistrationResponse,
    ServiceOperation,
    ServiceType,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use ieee1905::cmdu::CMDU;
use ieee1905::cmdu_codec::MessageVersion;

// Send response to transmitter containing complete SDU: (SDU + CMDU + TLVs)
// Only the TLV chain is a 1-to-1 copy without any modifications as SDU and CMDU headers
// need to be changed for proper SDU delivery
async fn send_echoed_packet(socket: &mut Framed<&mut UnixStream, LengthDelimitedCodec>, bytes: Vec<u8>) {
    println!("Sending SDU packet with copied TLV chain");

    let sdu = SDU::parse(bytes.as_slice());
    match sdu {
        Ok(res) => {
            let source_mac = res.1.source_al_mac_address;
            let destination_mac = res.1.destination_al_mac_address;
            let mut payload = res.1.payload;

            let cmdu_with_payload = CMDU::parse(&payload[..]);
            match cmdu_with_payload {
                Ok(res) => {
                    let mut cmdu = res.1;

                    // Workaround: enforce using Version2013 message in CMDU to get proper
                    // interpretation of vendor specific message on remote side (current
                    // implementation of CMDU handler needs this to invoke handle_sdu_from_cmdu_reception)
                    cmdu.message_version = MessageVersion::Version2013.to_u8();

                    payload = cmdu.serialize();
                }
                Err(e) => {
                    println!("Got parse error: {:?}", e);
                }
            }

            let sdu = SDU {
                source_al_mac_address: source_mac,
                destination_al_mac_address: destination_mac,
                is_fragment: 0,
                is_last_fragment: 1,
                fragment_id: 0,
                payload: payload,
            };

            println!("Sending SDU: source: {:?}  destination: {:?}", sdu.source_al_mac_address, sdu.destination_al_mac_address);

            // Assertion for proper SDU delivery to transmitter
            assert_eq!(sdu.payload[0], MessageVersion::Version2013.to_u8());

            let s = socket.send(bytes::Bytes::from(sdu.serialize())).await;
            println!("Sent echoed packet: {:?}", s);
        }
        Err(e) => {
            println!("Got parse error: {:?}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Modify this filter for your tracing during run time
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("trace")); //add 'tokio=trace' to debug the runtime

    // To show logs in stdout
    let fmt_layer = fmt::layer().with_target(true).with_level(true);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();

    println!("Starting functional tests: receiver side.");

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
                        tracing::trace!("Got some bytes: [{}] <{:?}>", bytes.len(), bytes);
                        tracing::trace!("Expecting id {:?}",fragment_id_expected);
                        match SDU::parse(&bytes) {
                            Ok(tuple) => {
                                tracing::trace!("Bytes parsed to SDU. Left bytes {:?}",tuple.0.len());
                                let fragment = tuple.1;
                                tracing::trace!("SDU: {:?}", fragment);
                                if fragment.is_fragment == 0 && fragment.is_last_fragment == 1 {
                                    // Single complete message
                                    let complete_sdu = fragment.clone();

                                    tracing::debug!("Sending single message");
                                    tracing::trace!("Got complete SDU [{}] <{complete_sdu:?}>", complete_sdu.payload.len());
                                    send_echoed_packet(&mut framed_data_socket, complete_sdu.serialize()).await;
                                    continue;
                                }

                                if fragment.fragment_id != fragment_id_expected {
                                    tracing::error!(
                                        "Fragment out of order expected {}, got {}",
                                        fragment_id_expected,
                                        fragment.fragment_id
                                    );
                                    panic!("Fragment out of order");
                                }
                                else{
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
                                    tracing::info!("Got reassembled SDU {final_message:?}");
                                    fragment_id_expected = 0;
                                    send_echoed_packet(&mut framed_data_socket, final_message.serialize()).await;
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
