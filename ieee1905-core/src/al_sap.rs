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
use crate::cmdu_proxy::cmdu_from_sdu_transmission;
use crate::ethernet_subject_transmission::EthernetSender;
use crate::interface_manager::get_local_al_mac;
use crate::registration_codec::{
    AlServiceRegistrationRequest, AlServiceRegistrationResponse, RegistrationResult,
    ServiceOperation, ServiceType,
};
use crate::sdu_codec::SDU;
use crate::topology_manager::Role;
use crate::{next_task_id, TopologyDatabase};
use anyhow::{bail, Context, Result};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use lazy_static::lazy_static;
use pnet::datalink::MacAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
// Internal modules
use crate::cmdu_codec::{CMDUFragmentation, IEEE1905TLVType, Profile2ApCapability, TLVTrait, CMDU};
use tokio::sync::oneshot;

use once_cell::sync::Lazy;

use crate::cmdu::{CMDUType, TLV};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

use sd_notify;
use sd_notify::NotifyState;

pub static SAP_INSTANCE: Lazy<Mutex<Option<Arc<Mutex<AlServiceAccessPoint>>>>> =
    Lazy::new(|| Mutex::new(None));

#[derive(Error, Debug)]
pub enum AlSapError {
    #[error("Socket closed by remote")]
    SocketClosed,
    #[error("Other error: {0}")]
    Other(String),
}

// Setter for SAP_INSTANCE
async fn set_instance(instance: AlServiceAccessPoint) -> Arc<Mutex<AlServiceAccessPoint>> {
    let mut lock = SAP_INSTANCE.lock().await;
    lock.insert(Arc::new(Mutex::new(instance))).clone()
}

// Getter for mutable access
async fn get_instance_mut() -> Option<Arc<Mutex<AlServiceAccessPoint>>> {
    let lock = SAP_INSTANCE.lock().await;
    lock.clone()
}

// Define type alias for Framed Unix Stream
type FramedUnix = Framed<UnixStream, LengthDelimitedCodec>;

// Two halves: read one and write one instead of one AlServiceAccessPoint.data_socket
lazy_static! {
    pub static ref LAZY_WRITER: Arc<Mutex<Option<SplitSink<FramedUnix, Bytes>>>> =
        Arc::new(Mutex::new(None));
    pub static ref LAZY_READER: Arc<Mutex<Option<SplitStream<FramedUnix>>>> =
        Arc::new(Mutex::new(None));
}

pub struct AlServiceAccessPoint {
    framed_control_socket: FramedUnix,
    control_socket_path: PathBuf,
    data_socket_path: PathBuf,
    sender: Arc<EthernetSender>,
    interface_name: String,
    enabled: bool,
    service_type: Option<ServiceType>,
}

impl AlServiceAccessPoint {
    #[instrument(skip_all, name = "al_sap_init", fields(task = next_task_id()))]
    pub async fn initialize_and_store(
        control_socket_path: impl AsRef<Path>,
        data_socket_path: impl AsRef<Path>,
        sender: Arc<EthernetSender>,
        interface_name: String,
        shutdown_tx: oneshot::Sender<()>,
    ) {
        let sap = AlServiceAccessPoint::start_server(
            control_socket_path,
            data_socket_path,
            sender,
            interface_name,
        )
        .await;

        let sap = match sap {
            Ok(e) => set_instance(e).await,
            Err(e) => return tracing::error!("Failed to initialize SAP: {e:?}"),
        };
        tracing::info!("SAP server initialized and stored.");

        let result = sap
            .lock()
            .await
            .service_access_point_registration_request()
            .await;
        tracing::debug!("SAP_INSTANCE locking result: {:?}", result);

        match result {
            Ok(_) => {
                tracing::debug!("Received registration request on control unix stream socket");
                sap_data_request_handler(shutdown_tx).await;
            }
            Err(err) => {
                tracing::error!("Registration request error: {:?}", err);
            }
        }
    }

    async fn start_server(
        control_socket_path: impl AsRef<Path>,
        data_socket_path: impl AsRef<Path>,
        sender: Arc<EthernetSender>,
        interface_name: String,
    ) -> Result<AlServiceAccessPoint> {
        tracing::info!("Starting server");
        let ctrl_path = control_socket_path.as_ref();
        let data_path = data_socket_path.as_ref();

        if ctrl_path.exists() {
            fs::remove_file(ctrl_path).await?;
        }
        if data_path.exists() {
            fs::remove_file(data_path).await?;
        }

        let control_listener = UnixListener::bind(ctrl_path)
            .with_context(|| format!("Failed to bind to control socket: {ctrl_path:?}"))?;
        let data_listener = UnixListener::bind(data_path)
            .with_context(|| format!("Failed to bind to data socket: {data_path:?}"))?;

        tracing::info!("Control socket listening at {:?}", ctrl_path);
        tracing::info!("Data socket listening at {:?}", data_path);

        // Notify systemd (when used) that we are ready to serve
        let _ = sd_notify::notify(false, &[NotifyState::Ready]);

        // Accept client connections (control and data)
        tracing::debug!("Waiting for sockets");
        let (control_socket, _) = control_listener.accept().await?;
        let framed_control_socket = Framed::new(control_socket, LengthDelimitedCodec::new());
        let (data_socket, _) = data_listener.accept().await?;
        let framed_data_socket = Framed::new(data_socket, LengthDelimitedCodec::new());

        // Initialize both: read and write halves for unix stream socket
        let (writer, reader) = framed_data_socket.split();
        let mut writer_lock = LAZY_WRITER.lock().await;
        *writer_lock = Some(writer);
        let mut reader_lock = LAZY_READER.lock().await;
        *reader_lock = Some(reader);

        Ok(AlServiceAccessPoint {
            framed_control_socket,
            control_socket_path: ctrl_path.to_path_buf(),
            data_socket_path: data_path.to_path_buf(),
            sender,
            interface_name,
            enabled: false,
            service_type: None,
        })
    }

    pub fn control_socket_path(&self) -> &Path {
        &self.control_socket_path
    }

    pub fn data_socket_path(&self) -> &Path {
        &self.data_socket_path
    }

    pub async fn control_is_connected(&mut self) -> bool {
        self.framed_control_socket
            .get_mut()
            .writable()
            .await
            .is_ok()
    }

    /// Receives a registration request from the socket (from a client)
    pub async fn service_access_point_registration_request(
        &mut self,
    ) -> Result<AlServiceRegistrationRequest> {
        if let Some(result) = self.framed_control_socket.next().await {
            match result {
                Ok(bytes) => {
                    let (_, request) =
                        AlServiceRegistrationRequest::parse(&bytes).map_err(|e| {
                            anyhow::anyhow!("Parse error in registration request: {:?}", e)
                        })?;

                    match request.service_operation {
                        ServiceOperation::Enable => {
                            self.enabled = true;
                        }
                        ServiceOperation::Disable => {
                            self.enabled = false;
                        }
                    };
                    self.service_type = Some(request.service_type);
                    match request.service_type {
                        ServiceType::EasyMeshAgent => {
                            tracing::info!("ServiceType EasyMeshAgent - Might be Enrollee");
                            let db = TopologyDatabase::get_instance(
                                get_local_al_mac(self.interface_name.clone()).unwrap(),
                                self.interface_name.clone(),
                            )
                            .await;
                            db.set_local_role(Some(Role::Enrollee)).await;
                        }
                        ServiceType::EasyMeshController => {
                            tracing::info!("ServiceType EasyMeshController - Might be Registrar");
                            let db = TopologyDatabase::get_instance(
                                get_local_al_mac(self.interface_name.clone()).unwrap(),
                                self.interface_name.clone(),
                            )
                            .await;
                            db.set_local_role(Some(Role::Registrar)).await;
                        }
                    };

                    // Calculate AL MAC Address (Derived from Forwarding Ethernet Interface)
                    let al_mac = if let Some(mac) = get_local_al_mac(self.interface_name.clone()) {
                        mac
                    } else {
                        tracing::debug!("No AL MAC ADDRESS calculated, using default.");
                        MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // Default AL MAC if not found
                    };

                    let response = AlServiceRegistrationResponse {
                        al_mac_address_local: al_mac,
                        message_id_range: (0, 65535),
                        result: RegistrationResult::Success,
                    };

                    let _ = self
                        .service_access_point_registration_response(&response)
                        .await;

                    return Ok(request);
                }
                Err(error) => {
                    tracing::error!("Error: {:?}", error);
                    return Err(error.into());
                }
            }
        }
        bail!("Fatal error while reading from control socket!")
    }

    /// Sends a registration response back to the client
    pub async fn service_access_point_registration_response(
        &mut self,
        response: &AlServiceRegistrationResponse,
    ) -> Result<()> {
        let serialized = response.serialize();
        self.framed_control_socket
            .send(Bytes::from(serialized.clone()))
            .await?;
        Ok(())
    }

    pub async fn check_if_role_match(&self, role: Role) -> bool {
        let db = TopologyDatabase::get_instance(
            get_local_al_mac(self.interface_name.clone()).unwrap(),
            self.interface_name.clone(),
        )
        .await;
        if let Some(local_role) = db.get_local_role().await {
            tracing::trace!("Compare local_role {local_role:?} with {role:?}");
            role == local_role
        } else {
            tracing::error!(
                "Local role not set in TopologyDB, should be alread set at this moment!"
            );
            false
        }
    }
}

/// Sends an SDU to the socket, fragmented if needed
pub async fn service_access_point_data_indication(sdu: &SDU) -> Result<()> {
    if let Some(sap_instance_arc) = get_instance_mut().await {
        let sap_instance = sap_instance_arc.lock().await;
        if !sap_instance.enabled {
            return Err(anyhow::anyhow!(
                "service_access_point_data_indication: SAP is not enabled"
            ));
        }
    }

    // Max packet size exchanged over UNIX socket is 65536.
    // Within this packet size we reserve 4 bytes for length delimited packet size
    // Then SDU header is of size 15 bytes (12 bytes for 2 mac addresses and 3 more bytes for flags)
    // It means that maximal size of SDU payload that can be send in one frame is:
    // 65536 - 4 - 15 = 65517
    const FRAGMENT_SIZE: usize = 65517;
    let total_size = sdu.payload.len();

    if total_size <= FRAGMENT_SIZE {
        tracing::trace!("No need to fragment SDU");
        let mut single_sdu = sdu.clone();
        single_sdu.is_fragment = 0;
        single_sdu.is_last_fragment = 1;
        single_sdu.fragment_id = 0;

        let serialized = single_sdu.serialize();
        let mut data_unix_write = LAZY_WRITER.lock().await;
        let Some(ref mut writer) = *data_unix_write else {
            bail!("LAZY_WRITER is not yet initialized");
        };

        match writer.send(Bytes::from(serialized)).await {
            Ok(_res) => {
                tracing::trace!("SDU from CMDU send success");
            }
            Err(e) => {
                tracing::error!("SDU from CMDU send ERROR: {e:?}");
            }
        }

        return Ok(());
    }
    tracing::trace!("SDU has to be fragmented SDU_PAYLOAD_SIZE: {total_size:?} MAX_PAYLOAD_SIZE: {FRAGMENT_SIZE:?}");
    let num_fragments = total_size.div_ceil(FRAGMENT_SIZE);
    tracing::trace!("SDU will be fragmented into {num_fragments:?} parts");
    for i in 0..num_fragments {
        let start = i * FRAGMENT_SIZE;
        let end = usize::min(start + FRAGMENT_SIZE, total_size);
        let fragment_payload = sdu.payload[start..end].to_vec();

        let fragment = SDU {
            source_al_mac_address: sdu.source_al_mac_address,
            destination_al_mac_address: sdu.destination_al_mac_address,
            is_fragment: 1,
            is_last_fragment: if i == num_fragments - 1 { 1 } else { 0 },
            fragment_id: i as u8,
            payload: fragment_payload,
        };
        tracing::trace!("Fragment: {i:?} SDU: {fragment:?}");
        let serialized = fragment.serialize();
        let mut data_unix_write = LAZY_WRITER.lock().await;
        let Some(ref mut writer) = *data_unix_write else {
            bail!("LAZY_WRITER is not yet initialized");
        };

        match writer.send(Bytes::from(serialized)).await {
            Ok(_res) => {
                tracing::trace!("SDU from CMDU send success");
            }
            Err(e) => {
                tracing::error!("SDU from CMDU send ERROR: {e:?}");
            }
        }
    }
    Ok(())
}

pub async fn intercept_roles_and_compare_with_local(tlvs: &[TLV]) {
    tracing::trace!("Intercepting role to check against topology database local role");
    let mut expected_role: Option<Role> = None;
    for tlv in tlvs {
        if tlv.tlv_type == IEEE1905TLVType::SearchedRole.to_u8() {
            //Registrar -- controller
            expected_role = Some(Role::Registrar);
            break;
        } else if tlv.tlv_type == IEEE1905TLVType::SupportedRole.to_u8() {
            //registry -- agent
            expected_role = Some(Role::Enrollee);
            break;
        }
    }
    if let Some(role) = expected_role {
        tracing::trace!("Comparing with role stored in topology database");
        if let Some(sap_instance_arc) = get_instance_mut().await {
            let sap_instance = sap_instance_arc.lock().await;
            //tracing::debug!("Got SAP_INSTANCE");
            let res = sap_instance.check_if_role_match(role).await;
            if res {
                tracing::trace!(
                    "Role match. SAP registered as {:?} wich match intercepted role: {:?}",
                    sap_instance.service_type,
                    role
                );
            } else {
                tracing::error!(
                    "Role mismatch! SAP registered as {:?} does not match intercepted role: {:?}",
                    sap_instance.service_type,
                    role
                );
            }
        }
    } else {
        tracing::warn!("No role to intercept!");
    }
}

pub async fn intercept_wcs_profile2_dpp_compatibility(
    cmdu: &CMDU,
    tlvs: &[TLV],
    destination: MacAddr,
) {
    if cmdu.message_type != CMDUType::ApAutoConfigWCS.to_u16() {
        return;
    }

    debug!(mac = %destination, "intercept_wcs_profile2_dpp_compatibility");
    let ap_capability = tlvs.iter().find_map(|e| {
        if e.tlv_type != IEEE1905TLVType::Profile2ApCapability.to_u8() {
            return None;
        }
        Some(Profile2ApCapability::parse(&e.tlv_value.as_ref()?).ok()?.1)
    });

    let Some(ap_capability) = ap_capability else {
        return debug!("Profile2ApCapability was not found");
    };

    let Some(db) = TopologyDatabase::peek_instance_sync() else {
        return warn!("failed to get TopologyDatabase");
    };

    let Some(mut node) = db.lock_node_by_port_mut(destination).await else {
        return warn!("node not found in database");
    };

    let fragmentation = match ap_capability.dpp_onboarding {
        true => CMDUFragmentation::ByteBoundary,
        false => CMDUFragmentation::TLVBoundary,
    };

    if node.device_data.supported_fragmentation != fragmentation {
        node.device_data.supported_fragmentation = fragmentation;
        info!("node {destination} fragmentation changed to {fragmentation:?}");
    }
}

pub async fn service_access_point_data_request() -> Result<SDU, AlSapError> {
    let mut assembled_payload = Vec::new();
    let mut fragment_id_expected = 0;
    let mut message: Option<SDU> = None;

    loop {
        tracing::debug!("Waiting for any data from unix stream socket");
        let mut data_unix_read = LAZY_READER.lock().await;
        tracing::debug!("Got lock on LAZY_RX");
        let Some(ref mut reader) = *data_unix_read else {
            return Err(AlSapError::Other(
                "Error while dereferencing LAZY_READER".into(),
            ));
        };
        let result_option = reader.next().await;
        tracing::debug!(
            "Got some data from unix stream socket: {:?}",
            &result_option
        );
        match result_option {
            Some(res) => {
                match res {
                    Ok(bytes_read) => {
                        tracing::debug!(
                            "Read {:?} bytes from unix stream data socket",
                            &bytes_read.len()
                        );
                        match SDU::parse(&bytes_read) {
                            Ok(tuple) => {
                                let fragment = tuple.1;
                                if fragment.is_fragment == 0 && fragment.is_last_fragment == 1 {
                                    // Single complete message
                                    let complete_sdu = fragment.clone();
                                    tracing::debug!("Sending single message");

                                    match send_cmdu_from_sdu(complete_sdu.clone()).await {
                                        Ok(()) => {
                                            tracing::trace!("Successfully sent CMDU from SDU");
                                            return Ok(complete_sdu);
                                        }
                                        Err(err) => {
                                            tracing::error!("Failed to send CMDU from SDU {err:?}");
                                            return Err(AlSapError::Other(format!(
                                                "Failed to send CMDU from SDU {err:?}"
                                            )));
                                        }
                                    }
                                }

                                if fragment.fragment_id != fragment_id_expected {
                                    tracing::error!(
                                        "Fragment out of order expected {}, got {}",
                                        fragment_id_expected,
                                        fragment.fragment_id
                                    );
                                    return Err(AlSapError::Other(format!(
                                        "Fragment out of order: expected {}, got {}",
                                        fragment_id_expected, fragment.fragment_id
                                    )));
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

                                assembled_payload.extend_from_slice(&fragment.payload);
                                if fragment.is_last_fragment == 1 {
                                    {
                                        // here is proper place to validate CMDU for size based fragmentation!

                                        match CMDU::parse(&assembled_payload) {
                                            Ok((_, parsed_cmd)) => {
                                                let Ok(tlvs) = parsed_cmd.get_tlvs() else {
                                                    tracing::error!(
                                                        "ReassembleSDU: Cannot parse CMDU TLVs"
                                                    );
                                                    return Err(AlSapError::Other(
                                                        "Error: Cannot parse CMDU TLVs".to_string(),
                                                    ));
                                                };
                                                if let Some(last_tlv) = tlvs.last() {
                                                    if last_tlv.tlv_type
                                                        != IEEE1905TLVType::EndOfMessage.to_u8()
                                                        || last_tlv.tlv_length != 0
                                                        || last_tlv.tlv_value.is_some()
                                                    {
                                                        tracing::error!("ReassembleSDU: Last is not end of message");
                                                        return Err(AlSapError::Other(
                                                            "Error: last TLV is not end of message"
                                                                .to_string(),
                                                        ));
                                                    }
                                                } else {
                                                    tracing::error!("ReassembleSDU: EoF");
                                                    return Err(AlSapError::Other(
                                                        "Error: EoF".to_string(),
                                                    ));
                                                }
                                            }
                                            Err(_) => {
                                                tracing::error!("ReassembleSDU: Cannot parse CMDU");
                                                return Err(AlSapError::Other(
                                                    "Error: Cannot parse CMDU".to_string(),
                                                ));
                                            }
                                        }
                                    }
                                    break;
                                }
                                fragment_id_expected += 1;
                            }
                            Err(e) => {
                                tracing::error!("Failed to parse SDU {e:?}");
                                return Err(AlSapError::Other("Failed to parse SDU".to_string()));
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Error {e:?}");
                        return Err(AlSapError::Other(format!("Error: {e:?}")));
                    }
                }
            }
            None => {
                tracing::debug!("Remote unix stream side has unexpectedly closed connection in the middle of SDU fragments transmission. Dropping this incomplete SDU instead of sending it through network.");
                return Err(AlSapError::SocketClosed);
            }
        }
    }

    let mut final_message =
        message.ok_or_else(|| AlSapError::Other("No fragments received".to_string()))?;
    final_message.payload = assembled_payload;

    let _result = send_cmdu_from_sdu(final_message.clone()).await;

    Ok(final_message)
}

// Do the downward forwarding: unix stream socket -> network
pub async fn sap_data_request_handler(shutdown_tx: oneshot::Sender<()>) {
    loop {
        match service_access_point_data_request().await {
            Ok(_) => {
                tracing::trace!("Connection active");
            }
            Err(AlSapError::SocketClosed) => {
                tracing::error!("Connection closed. Need to trigger restart!");
                let _ = shutdown_tx.send(());
                break;
            }
            Err(e) => {
                tracing::error!("Error: {:?}", e);
            }
        }
    }
    tracing::trace!("SAP_DATA_HANDLER_LOOP_DONE");
}

// Send CMDU from SDU
async fn send_cmdu_from_sdu(sdu: SDU) -> Result<()> {
    if let Ok((_, cmdu)) = CMDU::parse(&sdu.payload) {
        if let Ok(tlvs) = cmdu.get_tlvs() {
            intercept_roles_and_compare_with_local(&tlvs).await;
            intercept_wcs_profile2_dpp_compatibility(&cmdu, &tlvs, sdu.destination_al_mac_address)
                .await;
        } else {
            tracing::error!("SDU TLVs parse ERROR. We expect valid SDU/CMDU here!");
        }
    } else {
        tracing::error!("SDU payload parse ERROR. We expect valid SDU/CMDU here!");
    }

    if let Some(sap_instance_arc) = get_instance_mut().await {
        let sap_guard = sap_instance_arc.lock().await;

        if !sap_guard.enabled {
            return Err(anyhow::anyhow!(
                "Service_access_point_data_request: SAP is not enabled"
            ));
        }
        tracing::debug!("Sending CMDU part from SDU via network");
        cmdu_from_sdu_transmission(
            sap_guard.interface_name.clone(),
            sap_guard.sender.clone(),
            sdu.clone(),
        );
        Ok(())
    } else {
        tracing::warn!("SAP instance not ready, skipping registration");
        Err(anyhow::anyhow!(
            "Service_access_point_data_request: SAP is not enabled"
        ))
    }
}

pub fn data_is_connected() -> bool {
    true
}
