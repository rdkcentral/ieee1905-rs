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
pub mod al_sap;
pub mod artifact_exchange_service;
pub mod cmdu_codec;
pub mod cmdu_handler;
pub mod cmdu_message_id_generator;
pub mod cmdu_observer;
pub mod cmdu_proxy;
pub mod cmdu_reassembler;
#[cfg(feature = "crypto")]
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

pub mod lldpdu {
    pub use crate::lldpdu_codec::{ChassisId, LLDPDU, LLDPTLVType, PortId, TimeToLiveTLV};
    pub use crate::tlv_lldpdu_codec::TLV;
}

pub mod cmdu {
    pub use crate::cmdu_codec::{
        AlMacAddress, BridgingTuple, CMDU, CMDUType, DeviceBridgingCapability, DeviceInformation,
        IEEE1905Neighbor, IEEE1905TLVType, Ieee1905NeighborDevice, L2Neighbor, L2NeighborDevice,
        L2NeighborLocalInterface, LocalInterface, MacAddress,
        NonIEEE1905LocalInterfaceNeighborhood, NonIEEE1905Neighbor, NonIeee1905NeighborDevices,
        VendorSpecificInfo,
    };
    pub use crate::tlv_cmdu_codec::TLV;
}

pub use cmdu_message_id_generator::MessageIdGenerator;
pub use cmdu_observer::CMDUObserver;
pub use ethernet_subject_reception::EthernetReceiver;
pub use ethernet_subject_transmission::EthernetSender;
pub use lldpdu_observer::LLDPObserver;
pub use sdu_codec::SDU;
use std::future::Future;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::runtime::Handle;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
pub use topology_manager::TopologyDatabase;
use tracing::{Instrument, Span};

pub fn next_task_id() -> u32 {
    static TASK_ID: AtomicU32 = AtomicU32::new(0);
    TASK_ID.fetch_add(1, Ordering::Relaxed)
}

#[track_caller]
pub fn spawn_named<F>(name: impl AsRef<str>, future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    #[cfg(feature = "enable_tokio_console")]
    let handle = tokio::task::Builder::new()
        .name(name.as_ref())
        .spawn(future)
        .expect("runtime is dead");
    #[cfg(not(feature = "enable_tokio_console"))]
    let handle = {
        let _ = name;
        tokio::spawn(future)
    };
    handle
}

#[track_caller]
pub fn spawn_on_named<F>(
    name: impl AsRef<str>,
    runtime: &Handle,
    future: F,
) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    #[cfg(feature = "enable_tokio_console")]
    let handle = tokio::task::Builder::new()
        .name(name.as_ref())
        .spawn_on(future, runtime)
        .expect("runtime is dead");
    #[cfg(not(feature = "enable_tokio_console"))]
    let handle = {
        let _ = name;
        runtime.spawn(future)
    };
    handle
}

#[track_caller]
pub fn spawn_join_set_named<F>(
    name: impl AsRef<str>,
    span: Option<Span>,
    set: &mut JoinSet<F::Output>,
    future: F,
) -> AbortHandle
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    #[cfg(feature = "enable_tokio_console")]
    let handle = {
        let task = set.build_task().name(name.as_ref());
        let result = match span {
            None => task.spawn(future),
            Some(e) => task.spawn(future.instrument(e)),
        };
        result.expect("runtime is dead")
    };
    #[cfg(not(feature = "enable_tokio_console"))]
    let handle = {
        let _ = name;
        match span {
            None => set.spawn(future),
            Some(e) => set.spawn(future.instrument(e)),
        }
    };
    handle
}

#[track_caller]
pub fn spawn_join_set_blocking_named<F, T>(
    name: impl AsRef<str>,
    set: &mut JoinSet<F::Output>,
    function: F,
) -> AbortHandle
where
    F: FnOnce() -> T,
    F: Send + 'static,
    T: Send + 'static,
{
    #[cfg(feature = "enable_tokio_console")]
    let handle = set
        .build_task()
        .name(name.as_ref())
        .spawn_blocking(function)
        .expect("runtime is dead");
    #[cfg(not(feature = "enable_tokio_console"))]
    let handle = {
        let _ = name;
        set.spawn_blocking(function)
    };
    handle
}
