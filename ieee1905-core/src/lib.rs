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
// ───── Base modules ─────
pub mod al_sap;
pub mod cmdu_codec;
pub mod cmdu_handler;
pub mod cmdu_message_id_generator;
pub mod cmdu_observer;
pub mod cmdu_proxy;
pub mod cmdu_reassembler;
pub mod crypto_engine;
pub mod ethernet_subject_reception;
pub mod ethernet_subject_transmission;
pub mod interface_manager;
mod linux;
pub mod lldpdu_codec;
pub mod lldpdu_observer;
pub mod lldpdu_proxy;
pub mod registration_codec;
pub mod sdu_codec;
pub mod tlv_cmdu_codec;
pub mod tlv_lldpdu_codec;
pub mod topology_manager;

#[cfg(feature = "rbus")]
pub mod rbus;

// ───── Submodules: TLVs grouped under namespaces ─────
pub mod lldpdu {
    pub use crate::lldpdu_codec::{ChassisId, LLDPTLVType, PortId, TimeToLiveTLV, LLDPDU};
    pub use crate::tlv_lldpdu_codec::TLV;
}

pub mod cmdu {
    pub use crate::cmdu_codec::{
        AlMacAddress, BridgingTuple, CMDUType, DeviceBridgingCapability, DeviceInformation,
        IEEE1905Neighbor, IEEE1905TLVType, Ieee1905NeighborDevice, LocalInterface, MacAddress,
        NonIEEE1905LocalInterfaceNeighborhood, NonIEEE1905Neighbor, NonIeee1905NeighborDevices,
        VendorSpecificInfo, CMDU,
    };
    pub use crate::tlv_cmdu_codec::TLV;
}

use std::sync::atomic::{AtomicU32, Ordering};
// ───── Reexports: commonly used components ─────
pub use cmdu_message_id_generator::MessageIdGenerator;
pub use cmdu_observer::CMDUObserver;
pub use ethernet_subject_reception::EthernetReceiver;
pub use ethernet_subject_transmission::EthernetSender;
pub use lldpdu_observer::LLDPObserver;
pub use sdu_codec::SDU;
pub use topology_manager::TopologyDatabase;

pub fn next_task_id() -> u32 {
    static TASK_ID: AtomicU32 = AtomicU32::new(0);
    TASK_ID.fetch_add(1, Ordering::Relaxed)
}
