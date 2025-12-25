#![allow(non_camel_case_types)]

use crate::cmdu_codec::MediaType;
use crate::rbus::id::RBus_Ieee1905Id;
use crate::rbus::interface::RBus_Interface;
use crate::rbus::interface_len::RBus_InterfaceNumberOfEntries;
use crate::rbus::interface_link::RBus_InterfaceLink;
use crate::rbus::interface_link_len::RBus_InterfaceLinksLen;
use crate::rbus::nt_device::RBus_NetworkTopology_Ieee1905Device;
use crate::rbus::nt_device_bridge::RBus_NetworkTopology_Ieee1905Device_BridgingTuple;
use crate::rbus::nt_device_bridge_len::RBus_NetworkTopology_Ieee1905Device_BridgingTupleNumberOfEntries;
use crate::rbus::nt_device_bridge_list::RBus_NetworkTopology_Ieee1905Device_BridgingTuple_InterfaceList;
use crate::rbus::nt_device_id::RBus_NetworkTopology_Ieee1905Device_Ieee1905Id;
use crate::TopologyDatabase;
use anyhow::bail;
use pnet::datalink::MacAddr;
use rbus_core::RBusError;
use rbus_provider::element::object::rbus_object;
use rbus_provider::element::property::rbus_property;
use rbus_provider::element::table::rbus_table;
use rbus_provider::element::RBusProviderElement;
use rbus_provider::provider::{RBusProvider, RBusProviderError};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

mod id;
mod interface;
mod interface_len;
mod interface_link;
mod interface_link_len;
mod nt_device;
mod nt_device_bridge;
mod nt_device_bridge_len;
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
            rbus_object("Device", (
                rbus_object("IEEE1905", (
                    rbus_object("AL", (
                        rbus_object(format!("{instance}"), Self::register_nested()),
                    )),
                )),
            ))
        })
    }

    #[rustfmt::skip]
    fn register_nested() -> impl RBusProviderElement {
        (
            rbus_property("IEEE1905Id", RBus_Ieee1905Id),
            rbus_property("InterfaceNumberOfEntries", RBus_InterfaceNumberOfEntries),
            rbus_table("Interface", RBus_Interface, (
                rbus_property("InterfaceId", RBus_Interface),
                rbus_property("MediaType", RBus_Interface),
                rbus_property("LinkNumberOfEntries", RBus_InterfaceLinksLen),
                rbus_table("Link", RBus_InterfaceLink, (
                    rbus_property("IEEE1905Id", RBus_InterfaceLink),
                    rbus_property("InterfaceId", RBus_InterfaceLink),
                    rbus_property("MediaType", RBus_InterfaceLink),
                )),
            )),
            rbus_object("NetworkTopology", (
                rbus_table("IEEE1905Device", RBus_NetworkTopology_Ieee1905Device, (
                    rbus_property("IEEE1905Id", RBus_NetworkTopology_Ieee1905Device_Ieee1905Id),
                    rbus_property("BridgingTupleNumberOfEntries", RBus_NetworkTopology_Ieee1905Device_BridgingTupleNumberOfEntries),
                    rbus_table("BridgingTuple", RBus_NetworkTopology_Ieee1905Device_BridgingTuple, (
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

fn format_mac_address(mac: &MacAddr) -> String {
    mac.octets().map(|e| format!("{e:02X}")).join("-")
}

fn format_media_type(media_type: MediaType) -> &'static str {
    match media_type {
        MediaType::ETHERNET_802_3u => "IEEE 802.3u",
        MediaType::ETHERNET_802_3ab => "IEEE 802.3ab",
        MediaType::WIRELESS_802_11b_2_4 => "IEEE 802.11b",
        MediaType::WIRELESS_802_11g_2_4 => "IEEE 802.11g",
        MediaType::WIRELESS_802_11a_5 => "IEEE 802.11a",
        MediaType::WIRELESS_802_11n_2_4 => "IEEE 802.11n 2.4",
        MediaType::WIRELESS_802_11n_5 => "IEEE 802.11n 5.0",
        MediaType::WIRELESS_802_11ac_5 => "IEEE 802.11ac",
        MediaType::WIRELESS_802_11ad_60 => "IEEE 802.11ad",
        MediaType::WIRELESS_802_11af => "IEEE 802.11af",
        MediaType::WIRELESS_802_11ax => "IEEE 802.11ax",
        MediaType::WIRELESS_802_11be => "IEEE 802.11be",
        MediaType::IEEE_1901_Wavelet => "IEEE 1901 Wavelet",
        MediaType::IEEE_1901_FFT => "IEEE 1901 FFT",
        MediaType::MoCA_1_1 => "MoCAv1.1",
        _ => "Generic PHY",
    }
}
