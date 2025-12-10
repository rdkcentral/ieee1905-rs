#![allow(non_camel_case_types)]

use crate::rbus::id::RBus_Ieee1905Id;
use crate::rbus::nt_device::RBus_NetworkTopology_Ieee1905Device;
use crate::rbus::nt_device_bridge::RBus_NetworkTopology_Ieee1905Device_BridgingTuple;
use crate::rbus::nt_device_bridge_list::RBus_NetworkTopology_Ieee1905Device_BridgingTuple_InterfaceList;
use crate::rbus::nt_device_id::RBus_NetworkTopology_Ieee1905Device_Ieee1905Id;
use crate::TopologyDatabase;
use anyhow::bail;
use rbus_core::RBusError;
use rbus_provider::element::object::rbus_object;
use rbus_provider::element::property::rbus_property;
use rbus_provider::element::table::rbus_table;
use rbus_provider::element::RBusProviderElement;
use rbus_provider::provider::{RBusProvider, RBusProviderError};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

mod id;
mod nt_device;
mod nt_device_bridge;
mod nt_device_bridge_list;
mod nt_device_id;

///
/// Connection to RBus component
///
pub struct RBusConnection {
    _handle: RBusProvider,
}

impl RBusConnection {
    #[instrument(name = "rbus_open")]
    pub fn open() -> anyhow::Result<Self> {
        for instance in 0..4 {
            debug!(instance, "registering RBus elements");

            match Self::register(instance) {
                Ok(handle) => {
                    info!(instance, "RBus elements successfully registered");
                    return Ok(Self { _handle: handle });
                }
                Err(RBusProviderError::RBus(RBusError::ElementNameDuplication)) => {
                    warn!(instance, "RBus elements already registered");
                    continue;
                }
                Err(e) => bail!("failed to register RBus elements: {e}"),
            };
        }
        bail!("failed to register RBus elements, too many instances present");
    }

    #[rustfmt::skip]
    fn register(instance: u32) -> Result<RBusProvider, RBusProviderError> {
        RBusProvider::open(c"Device.IEEE1905", || {
            rbus_object("Device").content((
                rbus_object("IEEE1905").content((
                    rbus_object("AL").content((
                        rbus_object(format!("{instance}")).content(Self::register_nested()),
                    )),
                )),
            ))
        })
    }

    #[rustfmt::skip]
    fn register_nested() -> impl RBusProviderElement {
        (
            rbus_property("IEEE1905Id", RBus_Ieee1905Id),
            rbus_object("NetworkTopology").content((
                rbus_table("IEEE1905Device", RBus_NetworkTopology_Ieee1905Device).content((
                    rbus_property("IEEE1905Id", RBus_NetworkTopology_Ieee1905Device_Ieee1905Id),
                    rbus_table("BridgingTuple", RBus_NetworkTopology_Ieee1905Device_BridgingTuple).content((
                        rbus_property("InterfaceList", RBus_NetworkTopology_Ieee1905Device_BridgingTuple_InterfaceList),
                    ))
                )),
            )),
        )
    }
}

fn peek_topology_database() -> Result<&'static Arc<TopologyDatabase>, RBusError> {
    TopologyDatabase::peek_instance_sync().ok_or(RBusError::NotInitialized)
}
