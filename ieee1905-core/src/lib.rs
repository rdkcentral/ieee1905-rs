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
pub mod device_edge_manager;
pub mod ethernet_subject_reception;
pub mod ethernet_subject_transmission;
pub mod interface_manager;
pub mod lldpdu_codec;
pub mod lldpdu_observer;
pub mod lldpdu_proxy;
pub mod registration_codec;
pub mod sdu_codec;
pub mod tlv_cmdu_codec;
pub mod tlv_lldpdu_codec;
pub mod topology_manager;
pub mod task_registry;
pub mod crypto_engine;


// ───── Submodules: TLVs grouped under namespaces ─────
pub mod lldpdu {
    pub use crate::tlv_lldpdu_codec::TLV;
    pub use crate::lldpdu_codec::{
        ChassisId, LLDPTLVType, PortId, TimeToLiveTLV, LLDPDU,
    };
}

pub mod cmdu {
    pub use crate::tlv_cmdu_codec::TLV;
    pub use crate::cmdu_codec::{
        IEEE1905TLVType, CMDU, CMDUType,
        AlMacAddress, MacAddress, LocalInterface, DeviceInformation,
        BridgingTuple, DeviceBridgingCapability, VendorSpecificInfo,
        IEEE1905Neighbor, Ieee1905NeighborDevice,
        NonIEEE1905Neighbor, NonIEEE1905LocalInterfaceNeighborhood, NonIeee1905NeighborDevices,
    };
}

// ───── Reexports: commonly used components ─────
pub use sdu_codec::SDU;
pub use ethernet_subject_transmission::EthernetSender;
pub use ethernet_subject_reception::EthernetReceiver;
pub use lldpdu_observer::LLDPObserver;
pub use cmdu_observer::CMDUObserver;
pub use cmdu_message_id_generator::MessageIdGenerator;
pub use topology_manager::TopologyDatabase;
