#![allow(non_camel_case_types)]

use crate::TopologyDatabase;
use crate::cmdu_codec::MediaType;
use crate::rbus::al_device::RBus_Al_Device;
use crate::rbus::interface::RBus_Interface;
use crate::rbus::interface_link::RBus_InterfaceLink;
use crate::rbus::interface_link_metric::RBus_InterfaceLinkMetric;
use crate::rbus::network::RBus_Network;
use crate::rbus::network_al::RBus_Network_Al;
use crate::rbus::network_al_bridge_tuple::RBus_Network_Al_BridgingTuple;
use crate::rbus::network_al_interface::RBus_Network_Al_Interface;
use crate::rbus::network_al_interface_ieee1905_neighbor::RBus_Network_Al_Interface_Ieee1905Neighbor;
use crate::rbus::network_al_interface_l2_neighbor::RBus_Network_Al_Interface_L2Neighbor;
use crate::rbus::network_al_interface_link::RBus_Network_Al_Interface_Link;
use crate::rbus::network_al_interface_link_metric::RBus_Network_Al_Interface_Link_Metric;
use crate::rbus::network_al_interface_non_ieee1905_neighbor::RBus_Network_Al_Interface_NonIeee1905Neighbor;
use crate::rbus::network_al_ipv4::RBus_Network_Al_IPv4;
use crate::rbus::network_al_ipv6::RBus_Network_Al_IPv6;
use crate::rbus::nt::RBus_NetworkTopology;
use crate::rbus::nt_device::RBus_NetworkTopology_Ieee1905Device;
use crate::rbus::nt_device_bridge::RBus_NetworkTopology_Ieee1905Device_BridgingTuple;
use crate::rbus::nt_device_bridge_list::RBus_NetworkTopology_Ieee1905Device_BridgingTuple_InterfaceList;
use crate::rbus::nt_device_ieee1905_neighbor::RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor;
use crate::rbus::nt_device_ieee1905_neighbor_metric::RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric;
use crate::rbus::nt_device_ipv4::RBus_NetworkTopology_Ieee1905Device_IPv4;
use crate::rbus::nt_device_ipv6::RBus_NetworkTopology_Ieee1905Device_IPv6;
use crate::rbus::nt_device_l2_neighbor::RBus_NetworkTopology_Ieee1905Device_L2Neighbor;
use crate::rbus::nt_device_non_ieee1905_neighbor::RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor;
use anyhow::bail;
use rbus_core::{RBusError, RBusLibrary, RBusLogHandler, RBusLogLevel, RBusLogRecord};
use rbus_provider::element::RBusProviderElement;
use rbus_provider::element::object::rbus_object;
use rbus_provider::element::property::rbus_property;
use rbus_provider::element::table::rbus_table;
use rbus_provider::provider::{RBusProvider, RBusProviderError};
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};

mod al_device;
mod interface;
mod interface_link;
mod interface_link_metric;
mod network;
mod network_al;
mod network_al_bridge_tuple;
mod network_al_interface;
mod network_al_interface_ieee1905_neighbor;
mod network_al_interface_l2_neighbor;
mod network_al_interface_link;
mod network_al_interface_link_metric;
mod network_al_interface_non_ieee1905_neighbor;
mod network_al_ipv4;
mod network_al_ipv6;
mod nt;
mod nt_device;
mod nt_device_bridge;
mod nt_device_bridge_list;
mod nt_device_ieee1905_neighbor;
mod nt_device_ieee1905_neighbor_metric;
mod nt_device_ipv4;
mod nt_device_ipv6;
mod nt_device_l2_neighbor;
mod nt_device_non_ieee1905_neighbor;

///
/// Connection to RBus component
///
pub struct RBusConnection {
    _handle: RBusProvider,
}

impl RBusConnection {
    #[instrument(name = "rbus_open")]
    pub fn open() -> anyhow::Result<Self> {
        let library = RBusLibrary::load()?;

        if let Err(e) = library.register_log_handler::<RBusLogger>() {
            warn!("failed to register log handler: {e}");
        }

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
                    rbus_object("Network", (
                        rbus_object(format!("{instance}"), Self::build_network(instance)),
                    )),
                )),
            ))
        })
    }

    #[rustfmt::skip]
    fn register_nested() -> impl RBusProviderElement {
        (
            rbus_property("IEEE1905Id", RBus_Al_Device),
            rbus_property("InterfaceNumberOfEntries", RBus_Al_Device),
            rbus_table("Interface", RBus_Interface, (
                rbus_property("InterfaceId", RBus_Interface),
                rbus_property("MediaType", RBus_Interface),
                rbus_property("LinkNumberOfEntries", RBus_Interface),
                rbus_table("Link", RBus_InterfaceLink, (
                    rbus_property("IEEE1905Id", RBus_InterfaceLink),
                    rbus_property("InterfaceId", RBus_InterfaceLink),
                    rbus_property("MediaType", RBus_InterfaceLink),
                    rbus_object("Metric", (
                        rbus_property("IEEE802dot1Bridge", RBus_InterfaceLinkMetric),
                        rbus_property("PacketErrors", RBus_InterfaceLinkMetric),
                        rbus_property("PacketErrorsReceived", RBus_InterfaceLinkMetric),
                        rbus_property("TransmittedPackets", RBus_InterfaceLinkMetric),
                        rbus_property("PacketsReceived", RBus_InterfaceLinkMetric),
                        rbus_property("MACThroughputCapacity", RBus_InterfaceLinkMetric),
                        rbus_property("LinkAvailability", RBus_InterfaceLinkMetric),
                        rbus_property("PHYRate", RBus_InterfaceLinkMetric),
                        rbus_property("RSSI", RBus_InterfaceLinkMetric),
                    )),
                )),
            )),
            rbus_object("NetworkTopology", (
                rbus_property("IEEE1905DeviceNumberOfEntries", RBus_NetworkTopology),
                rbus_table("IEEE1905Device", RBus_NetworkTopology_Ieee1905Device, (
                    (
                        rbus_property("IEEE1905Id", RBus_NetworkTopology_Ieee1905Device),
                        rbus_property("Version", RBus_NetworkTopology_Ieee1905Device),
                        rbus_property("RegistrarFreqBand", RBus_NetworkTopology_Ieee1905Device),
                        rbus_property("FriendlyName", RBus_NetworkTopology_Ieee1905Device),
                        rbus_property("ManufacturerName", RBus_NetworkTopology_Ieee1905Device),
                        rbus_property("ManufacturerModel", RBus_NetworkTopology_Ieee1905Device),
                    ),
                    (
                        rbus_property("L2NeighborNumberOfEntries", RBus_NetworkTopology_Ieee1905Device),
                        rbus_table("L2Neighbor", RBus_NetworkTopology_Ieee1905Device_L2Neighbor, (
                            rbus_property("LocalInterface", RBus_NetworkTopology_Ieee1905Device_L2Neighbor),
                            rbus_property("NeighborInterfaceId", RBus_NetworkTopology_Ieee1905Device_L2Neighbor),
                            rbus_property("BehindInterfaceIds", RBus_NetworkTopology_Ieee1905Device_L2Neighbor),
                        )),
                    ),
                    (
                        rbus_property("BridgingTupleNumberOfEntries", RBus_NetworkTopology_Ieee1905Device),
                        rbus_table("BridgingTuple", RBus_NetworkTopology_Ieee1905Device_BridgingTuple, (
                            rbus_property("InterfaceList", RBus_NetworkTopology_Ieee1905Device_BridgingTuple_InterfaceList),
                        )),
                    ),
                    (
                        rbus_property("IEEE1905NeighborNumberOfEntries", RBus_NetworkTopology_Ieee1905Device),
                        rbus_table("IEEE1905Neighbor", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor, (
                            rbus_property("LocalInterface", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor),
                            rbus_property("NeighborDeviceId", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor),
                            rbus_property("MetricNumberOfEntries", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor),
                            rbus_table("Metric", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric, (
                                rbus_property("NeighborMACAddress", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric),
                                rbus_property("IEEE802dot1Bridge", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric),
                                rbus_property("PacketErrors", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric),
                                rbus_property("PacketErrorsReceived", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric),
                                rbus_property("TransmittedPackets", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric),
                                rbus_property("PacketsReceived", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric),
                                rbus_property("MACThroughputCapacity", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric),
                                rbus_property("LinkAvailability", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric),
                                rbus_property("PHYRate", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric),
                                rbus_property("RSSI", RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric),
                            )),
                        )),
                    ),
                    (
                        rbus_property("NonIEEE1905NeighborNumberOfEntries", RBus_NetworkTopology_Ieee1905Device),
                        rbus_table("NonIEEE1905Neighbor", RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor, (
                            rbus_property("LocalInterface", RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor),
                            rbus_property("NeighborInterfaceId", RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor),
                        )),
                    ),
                    (
                        rbus_property("IPv4AddressNumberOfEntries", RBus_NetworkTopology_Ieee1905Device),
                        rbus_table("IPv4Address", RBus_NetworkTopology_Ieee1905Device_IPv4, (
                            rbus_property("MACAddress", RBus_NetworkTopology_Ieee1905Device_IPv4),
                            rbus_property("IPv4Address", RBus_NetworkTopology_Ieee1905Device_IPv4),
                            rbus_property("IPv4AddressType", RBus_NetworkTopology_Ieee1905Device_IPv4),
                            rbus_property("DHCPServer", RBus_NetworkTopology_Ieee1905Device_IPv4),
                        )),
                    ),
                    (
                        rbus_property("IPv6AddressNumberOfEntries", RBus_NetworkTopology_Ieee1905Device),
                        rbus_table("IPv6Address", RBus_NetworkTopology_Ieee1905Device_IPv6, (
                            rbus_property("MACAddress", RBus_NetworkTopology_Ieee1905Device_IPv6),
                            rbus_property("IPv6Address", RBus_NetworkTopology_Ieee1905Device_IPv6),
                            rbus_property("IPv6AddressType", RBus_NetworkTopology_Ieee1905Device_IPv6),
                            rbus_property("IPv6AddressOrigin", RBus_NetworkTopology_Ieee1905Device_IPv6),
                        )),
                    ),
                )),
            )),
        )
    }

    #[rustfmt::skip]
    fn build_network(instance: u32) -> impl RBusProviderElement {
        (
            rbus_property("Status", RBus_Network),
            rbus_property("ALNumberOfEntries", RBus_Network),
            rbus_table("AL", RBus_Network_Al, (
                (
                    rbus_property("IEEE1905Id", RBus_Network_Al),
                    rbus_property("Version", RBus_Network_Al),
                    rbus_property("RegistrarFreqBand", RBus_Network_Al),
                    rbus_property("FriendlyName", RBus_Network_Al),
                    rbus_property("ManufacturerName", RBus_Network_Al),
                    rbus_property("ManufacturerModel", RBus_Network_Al),
                    rbus_property("ControlURL", RBus_Network_Al),
                ),
                (
                    rbus_property("IPv4AddressNumberOfEntries", RBus_Network_Al),
                    rbus_table("IPv4Address", RBus_Network_Al_IPv4, (
                        rbus_property("MACAddress", RBus_Network_Al_IPv4),
                        rbus_property("IPv4Address", RBus_Network_Al_IPv4),
                        rbus_property("IPv4AddressType", RBus_Network_Al_IPv4),
                        rbus_property("DHCPServer", RBus_Network_Al_IPv4),
                    ))
                ),
                (
                    rbus_property("IPv6AddressNumberOfEntries", RBus_Network_Al),
                    rbus_table("IPv6Address", RBus_Network_Al_IPv6, (
                        rbus_property("MACAddress", RBus_Network_Al_IPv6),
                        rbus_property("IPv6Address", RBus_Network_Al_IPv6),
                        rbus_property("IPv6AddressType", RBus_Network_Al_IPv6),
                        rbus_property("IPv6AddressOrigin", RBus_Network_Al_IPv6),
                    ))
                ),
                (
                    rbus_property("BridgingTupleNumberOfEntries", RBus_Network_Al),
                    rbus_table("BridgingTuple", RBus_Network_Al_BridgingTuple, (
                        rbus_property("InterfaceList", RBus_Network_Al_BridgingTuple),
                    ))
                ),
                (
                    rbus_property("InterfaceNumberOfEntries", RBus_Network_Al),
                    rbus_table("Interface", RBus_Network_Al_Interface, (
                        (
                            rbus_property("InterfaceId", RBus_Network_Al_Interface),
                            rbus_property("MediaType", RBus_Network_Al_Interface),
                            rbus_property("PowerState", RBus_Network_Al_Interface),
                            rbus_property("NetworkMembership", RBus_Network_Al_Interface),
                            rbus_property("Role", RBus_Network_Al_Interface),
                            rbus_property("APChannelBand", RBus_Network_Al_Interface),
                            rbus_property("FrequencyIndex1", RBus_Network_Al_Interface),
                            rbus_property("FrequencyIndex2", RBus_Network_Al_Interface),
                        ),
                        (
                            rbus_property("LinkNumberOfEntries", RBus_Network_Al_Interface),
                            rbus_table("Link", RBus_Network_Al_Interface_Link, (
                                rbus_property("InterfaceId", RBus_Network_Al_Interface_Link),
                                rbus_property("IEEE1905Id", RBus_Network_Al_Interface_Link),
                                rbus_property("MediaType", RBus_Network_Al_Interface_Link),
                                rbus_object("Metric", (
                                    rbus_property("IEEE802dot1Bridge", RBus_Network_Al_Interface_Link_Metric),
                                    rbus_property("PacketErrors", RBus_Network_Al_Interface_Link_Metric),
                                    rbus_property("PacketErrorsReceived", RBus_Network_Al_Interface_Link_Metric),
                                    rbus_property("TransmittedPackets", RBus_Network_Al_Interface_Link_Metric),
                                    rbus_property("PacketsReceived", RBus_Network_Al_Interface_Link_Metric),
                                    rbus_property("MACThroughputCapacity", RBus_Network_Al_Interface_Link_Metric),
                                    rbus_property("LinkAvailability", RBus_Network_Al_Interface_Link_Metric),
                                    rbus_property("PHYRate", RBus_Network_Al_Interface_Link_Metric),
                                    rbus_property("RSSI", RBus_Network_Al_Interface_Link_Metric),
                                )),
                            )),
                        ),
                        (
                            rbus_property("IEEE1905NeighborNumberOfEntries", RBus_Network_Al_Interface),
                            rbus_table("IEEE1905Neighbor", RBus_Network_Al_Interface_Ieee1905Neighbor { instance }, (
                                rbus_property("NeighborDeviceId", RBus_Network_Al_Interface_Ieee1905Neighbor { instance }),
                                rbus_property("IEEE1905DeviceRef", RBus_Network_Al_Interface_Ieee1905Neighbor { instance }),
                                rbus_property("IEEE802dot1Bridge", RBus_Network_Al_Interface_Ieee1905Neighbor { instance }),
                            )),
                        ),
                        (
                            rbus_property("NonIEEE1905NeighborNumberOfEntries", RBus_Network_Al_Interface),
                            rbus_table("NonIEEE1905Neighbor", RBus_Network_Al_Interface_NonIeee1905Neighbor, (
                                rbus_property("NeighborInterfaceId", RBus_Network_Al_Interface_NonIeee1905Neighbor),
                            )),
                        ),
                        (
                            rbus_property("L2NeighborNumberOfEntries", RBus_Network_Al_Interface),
                            rbus_table("L2Neighbor", RBus_Network_Al_Interface_L2Neighbor, (
                                rbus_property("NeighborInterfaceId", RBus_Network_Al_Interface_L2Neighbor),
                                rbus_property("BehindInterfaceIds", RBus_Network_Al_Interface_L2Neighbor),
                            )),
                        ),
                    ))
                ),
            )),
        )
    }
}

fn peek_topology_database() -> Result<&'static Arc<TopologyDatabase>, RBusError> {
    TopologyDatabase::peek_instance_sync().ok_or(RBusError::NotInitialized)
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

struct RBusLogger;

impl RBusLogHandler for RBusLogger {
    fn print_log(record: RBusLogRecord) {
        match record.level {
            RBusLogLevel::Debug => debug!("[rbus] {:?}", record.message),
            RBusLogLevel::Info => info!("[rbus] {:?}", record.message),
            RBusLogLevel::Warn => warn!("[rbus] {:?}", record.message),
            _ => error!("[rbus] {:?}", record.message),
        }
    }
}
