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

use netdev::interface::types::InterfaceType;
use pnet::datalink::{self, MacAddr};
use std::net::Ipv6Addr;

use crate::cmdu_codec::{MediaType, MediaTypeSpecialInfo, MediaTypeSpecialInfoWifi};
use crate::linux::eth_tool::{
    ETH_TOOL_GENL_NAME, EthToolBitsetAttr, EthToolBitsetBitAttr, EthToolHeaderAttribute,
    EthToolLinkMode, EthToolLinkModesAttribute, EthToolMessage,
};
use crate::linux::if_link::{RtnlLinkStats, RtnlLinkStats64};
use crate::linux::nl80211::{
    NL80211_GENL_NAME, Nl80211Attribute, Nl80211Band, Nl80211BandAttr, Nl80211BandIfTypeAttr,
    Nl80211BitrateAttr, Nl80211ChannelWidth, Nl80211Command, Nl80211IfType, Nl80211RateInfo,
    Nl80211StaInfo, Nl80211SurveyInfoAttr,
};
use crate::topology_manager::{Ieee1905InterfaceData, Ieee1905LocalInterface};
use indexmap::{IndexMap, IndexSet};
use neli::consts::nl::{GenlId, NlmF};
use neli::consts::rtnl::{
    Arphrd, Ifa, IfaF, Iff, Ifla, IflaInfo, IflaVlan, Nda, Ntf, Nud, RtAddrFamily, RtScope, Rtm,
    Rtn,
};
use neli::consts::socket::NlFamily;
use neli::genl::{AttrTypeBuilder, GenlAttrHandle, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder};
use neli::nl::{NlPayload, Nlmsghdr, NlmsghdrBuilder};
use neli::router::asynchronous::{NlRouter, NlRouterReceiverHandle};
use neli::rtnl::{
    Ifaddrmsg, IfaddrmsgBuilder, Ifinfomsg, IfinfomsgBuilder, Ndmsg, NdmsgBuilder, RtAttrHandle,
    RtattrBuilder,
};
use neli::socket::asynchronous::NlSocketHandle;
use neli::types::{GenlBuffer, RtBuffer};
use neli::utils::Groups;
use std::ops::{BitAnd, Div};
use tracing::{debug, error, trace, warn};

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub mac: MacAddr,
    pub if_index: u32,
    pub if_name: String,
}

pub fn get_local_al_mac(interface_name: String) -> Option<MacAddr> {
    // Fetch all network interfaces
    let interfaces = datalink::interfaces();

    // Find the first Ethernet interface (`ethX`)
    if let Some(iface) = interfaces
        .iter()
        .find(|iface| iface.name.starts_with(&interface_name))
    {
        return iface.mac;
    }
    tracing::debug!("No Al Mac found, using default.");
    Some(MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
}

pub fn get_interface_info(if_name: &str) -> Option<InterfaceInfo> {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(|e| e.name == if_name)?;
    Some(InterfaceInfo {
        mac: interface.mac?,
        if_index: interface.index,
        if_name: interface.name,
    })
}

pub fn get_forwarding_interface_mac(interface_name: &str) -> MacAddr {
    // Fetch all network interfaces
    let interfaces = datalink::interfaces();

    // Find the first Ethernet interface (`ethX`)
    if let Some(mac_addr) = interfaces
        .iter()
        .find(|iface| iface.name.starts_with(interface_name))
        .and_then(|iface| iface.mac)
    {
        tracing::debug!("Ethernet interface found for forwarding {mac_addr}");
        mac_addr
    } else {
        tracing::debug!("No Ethernet interface found for forwarding, using default.");
        MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    }
}

/// **Gets the MAC address of a given network interface**
pub fn get_mac_address_by_interface(interface_name: &str) -> Option<MacAddr> {
    // Fetch all available interfaces
    let interfaces = datalink::interfaces();

    // Find the interface by name and return its MAC address
    interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .and_then(|iface| iface.mac) // Extract MAC address if found
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GetInterfacesResult {
    pub radios: Vec<WirelessRadioBss>,
    pub interfaces: Vec<Ieee1905LocalInterface>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WirelessRadioBss {
    pub radio_unique_id: MacAddr,
    pub bss_list: Vec<WirelessBssInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirelessBssInfo {
    pub if_name: String,
    pub bssid: MacAddr,
    pub ssid: Vec<u8>,
}

pub async fn get_interfaces(forwarding_if_name: &str) -> anyhow::Result<GetInterfacesResult> {
    let mut result = GetInterfacesResult::default();
    let mut links = get_link_interfaces().await?;

    // filter out interfaces that are not bridged with the forwarding interfaces
    filter_interfaces_by_bridge(forwarding_if_name, &mut links).await;

    // filter out veth (virtual) interfaces
    links.retain(|_, e| e.if_name == forwarding_if_name || e.link_kind.as_deref() != Some("veth"));

    match get_wireless_interfaces(&mut links).await {
        Ok((radios, interfaces)) => {
            result.radios = radios;
            result.interfaces.extend(interfaces);
        }
        Err(e) => error!(%e, "get_wireless_interfaces failed"),
    }

    match get_ethernet_interfaces(&links).await {
        Ok(e) => result.interfaces.extend(e),
        Err(e) => error!(%e, "get_ethernet_interfaces failed"),
    }

    trace!("get_interfaces => {result:#?}");
    Ok(result)
}

async fn get_link_interfaces() -> anyhow::Result<IndexMap<i32, LinkInterfaceInfo>> {
    let mut links = call_rt_get_links().await?;
    let mut bridge_fdb_neighbors = call_rt_get_bridge_fdb().await?;

    // remove all local interfaces from bridge fdb
    for link in links.iter() {
        bridge_fdb_neighbors.swap_remove(&link.1.mac);
    }

    // add neighbors to link interfaces
    for (neighbor, if_indexes) in bridge_fdb_neighbors {
        for if_index in if_indexes {
            if let Some(link) = links.get_mut(&if_index) {
                link.neighbours.insert(neighbor);
            }
        }
    }
    Ok(links)
}

async fn filter_interfaces_by_bridge(
    forwarding_if_name: &str,
    links: &mut IndexMap<i32, LinkInterfaceInfo>,
) {
    if filter_interfaces_by_ovs_bridge(forwarding_if_name, links).await {
        return;
    }
    if filter_interfaces_by_linux_bridge(forwarding_if_name, links) {
        return;
    }
    debug!("forwarding interface has no bridge, removing others");
    links.retain(|_, e| e.if_name == forwarding_if_name);
}

async fn filter_interfaces_by_ovs_bridge(
    forwarding_if_name: &str,
    links: &mut IndexMap<i32, LinkInterfaceInfo>,
) -> bool {
    let mut bridge_child_if_name = forwarding_if_name;

    // select other veth pair endpoint if current endpoint is not connected to the bridge
    if let Some(forwarding_interface) = links.values().find(|e| e.if_name == bridge_child_if_name)
        && forwarding_interface.link_kind.as_deref() == Some("veth")
        && forwarding_interface.bridge_if_index.is_none()
        && let Some(pair_if_index) = forwarding_interface.link_if_index
        && let Some(pair_interface) = links.get(&pair_if_index)
    {
        bridge_child_if_name = pair_interface.if_name.as_str();
    }

    let bridge = match call_ovs_interface_to_bridge(bridge_child_if_name).await {
        Ok(e) => e,
        Err(e) => {
            debug!(%e, "ovs bridge not available");
            return false;
        }
    };

    let interfaces = match call_ovs_list_bridge_interfaces(&bridge).await {
        Ok(e) => e,
        Err(e) => {
            error!(bridge, %e, "call_ovs_list_bridge_interfaces failed");
            return false;
        }
    };

    debug!("filtering interfaces by {bridge:?} ovs bridge");
    links.retain(|_, e| e.if_name == forwarding_if_name || interfaces.contains(&e.if_name));
    true
}

fn filter_interfaces_by_linux_bridge(
    forwarding_if_name: &str,
    links: &mut IndexMap<i32, LinkInterfaceInfo>,
) -> bool {
    let Some(mut interface) = links.values().find(|e| e.if_name == forwarding_if_name) else {
        warn!("forwarding interface {forwarding_if_name:?} not found, filtering skipped");
        return false;
    };

    // select other veth pair endpoint if current endpoint is not connected to the bridge
    if interface.link_kind.as_deref() == Some("veth")
        && interface.bridge_if_index.is_none()
        && let Some(pair_if_index) = interface.link_if_index
        && let Some(pair_interface) = links.get(&pair_if_index)
    {
        interface = pair_interface;
    }

    // find interface bridge
    let bridge = if interface.link_kind.as_deref() == Some("bridge") {
        interface
    } else if let Some(bridge_if_index) = interface.bridge_if_index
        && let Some(bridge) = links.get(&(bridge_if_index as i32))
    {
        bridge
    } else {
        return false;
    };

    debug!("filtering interfaces by {:?} Linux bridge", bridge.if_name);
    let bridge_if_index = bridge.if_index as u32;
    links.retain(|_, e| {
        e.if_name == forwarding_if_name || e.bridge_if_index == Some(bridge_if_index)
    });
    true
}

#[derive(Debug)]
struct LinkInterfaceInfo {
    mac: MacAddr,
    if_index: i32,
    if_name: String,
    if_flags: Iff,
    link_kind: Option<String>,
    link_if_index: Option<i32>,
    bridge_if_index: Option<u32>,
    vlan_id: Option<u16>,
    link_stats: Option<RtnlLinkStats64>,
    neighbours: IndexSet<MacAddr>,
}

async fn call_rt_get_links() -> anyhow::Result<IndexMap<i32, LinkInterfaceInfo>> {
    let (router, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty()).await?;
    let if_info_msg = IfinfomsgBuilder::default()
        .ifi_family(RtAddrFamily::Unspecified)
        .build()?;

    let mut recv: NlRouterReceiverHandle<Rtm, Ifinfomsg> = router
        .send(
            Rtm::Getlink,
            NlmF::DUMP | NlmF::ACK,
            NlPayload::Payload(if_info_msg),
        )
        .await?;

    let mut interfaces = IndexMap::new();
    while let Some(message) = recv.next().await {
        let message: Nlmsghdr<Rtm, Ifinfomsg> = message?;
        let Some(payload) = message.get_payload() else {
            continue;
        };

        let attr_handle = payload.rtattrs().get_attr_handle();
        if payload.ifi_type() != &Arphrd::Ether {
            continue;
        }
        let Ok(mac) = attr_handle.get_attr_payload_as::<[u8; 6]>(Ifla::Address) else {
            continue;
        };
        let Ok(if_name) = attr_handle.get_attr_payload_as_with_len::<String>(Ifla::Ifname) else {
            continue;
        };

        let mut vlan_id = None;
        let mut link_kind = None;
        if let Ok(link_info) = attr_handle.get_nested_attributes(Ifla::Linkinfo)
            && let Ok(kind) = link_info.get_attr_payload_as_with_len::<String>(IflaInfo::Kind)
        {
            link_kind = Some(kind.clone()).filter(|s| !s.is_empty());

            if kind.as_str() == "vlan"
                && let Ok(data) = link_info.get_nested_attributes(IflaInfo::Data)
            {
                vlan_id = data.get_attr_payload_as(IflaVlan::Id).ok();
            }
        }

        let if_flags = *payload.ifi_flags();
        let if_index = *payload.ifi_index();
        let link_if_index = attr_handle.get_attr_payload_as(Ifla::Link).ok();
        let bridge_if_index = attr_handle.get_attr_payload_as(Ifla::Master).ok();
        let link_stats = get_link_stats(&attr_handle);
        trace!(
            if_name = %if_name,
            if_index,
            ?link_kind,
            ?link_if_index,
            ?bridge_if_index,
            "parsed link interface",
        );

        let interface_info = LinkInterfaceInfo {
            mac: MacAddr::from(mac),
            if_index,
            if_name,
            if_flags,
            link_kind,
            link_if_index,
            bridge_if_index,
            vlan_id,
            link_stats,
            neighbours: Default::default(),
        };
        interfaces.insert(if_index, interface_info);
    }

    Ok(interfaces)
}

async fn call_rt_get_bridge_fdb() -> anyhow::Result<IndexMap<MacAddr, IndexSet<i32>>> {
    let (router, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty()).await?;

    const AF_BRIDGE: u8 = 7;
    let if_info_msg = NdmsgBuilder::default()
        .ndm_family(RtAddrFamily::from(AF_BRIDGE))
        .ndm_index(0)
        .ndm_state(Nud::empty())
        .ndm_flags(Ntf::empty())
        .ndm_type(Rtn::Unicast)
        .build()?;

    let mut recv: NlRouterReceiverHandle<Rtm, Ndmsg> = router
        .send(
            Rtm::Getneigh,
            NlmF::DUMP | NlmF::REQUEST | NlmF::ACK,
            NlPayload::Payload(if_info_msg),
        )
        .await?;

    let mut result = IndexMap::new();
    while let Some(message) = recv.next().await {
        let message: Nlmsghdr<Rtm, Ndmsg> = message?;
        let Some(payload) = message.get_payload() else {
            continue;
        };

        // we need only learned records, not locally assigned
        if *payload.ndm_state() == Nud::PERMANENT {
            continue;
        }

        let attr_handle = payload.rtattrs().get_attr_handle();
        let Ok(mac) = attr_handle.get_attr_payload_as::<[u8; 6]>(Nda::Lladdr) else {
            continue;
        };

        let mac = MacAddr::from(mac);
        let if_index = *payload.ndm_index();

        result
            .entry(mac)
            .or_insert_with(IndexSet::new)
            .insert(if_index);
    }
    Ok(result)
}

pub async fn call_rt_new_address_v6(if_index: u32, address: Ipv6Addr) -> anyhow::Result<()> {
    let socket = NlSocketHandle::connect(NlFamily::Route, None, Groups::empty())?;

    let rt_attrs = RtBuffer::from_iter([
        RtattrBuilder::default()
            .rta_type(Ifa::Local)
            .rta_payload(address.octets())
            .build()?,
        RtattrBuilder::default()
            .rta_type(Ifa::Address)
            .rta_payload(address.octets())
            .build()?,
    ]);

    let rt_message = IfaddrmsgBuilder::default()
        .ifa_family(RtAddrFamily::Inet6)
        .ifa_prefixlen(64)
        .ifa_flags(IfaF::NODAD)
        .ifa_scope(RtScope::Link)
        .ifa_index(if_index)
        .rtattrs(rt_attrs)
        .build()?;

    let rt_header = NlmsghdrBuilder::default()
        .nl_type(Rtm::Newaddr)
        .nl_flags(NlmF::REQUEST | NlmF::CREATE | NlmF::ACK | NlmF::EXCL)
        .nl_payload(NlPayload::Payload(rt_message))
        .build()?;

    socket.send(&rt_header).await?;
    socket.recv_all::<u16, Ifaddrmsg>().await?;
    Ok(())
}

pub async fn call_rt_remove_address_v6(if_index: u32, address: Ipv6Addr) -> anyhow::Result<()> {
    let socket = NlSocketHandle::connect(NlFamily::Route, None, Groups::empty())?;

    let rt_attrs = RtBuffer::from_iter([
        RtattrBuilder::default()
            .rta_type(Ifa::Local)
            .rta_payload(address.octets())
            .build()?,
        RtattrBuilder::default()
            .rta_type(Ifa::Address)
            .rta_payload(address.octets())
            .build()?,
    ]);

    let rt_message = IfaddrmsgBuilder::default()
        .ifa_family(RtAddrFamily::Inet6)
        .ifa_prefixlen(64)
        .ifa_flags(IfaF::empty())
        .ifa_scope(RtScope::Link)
        .ifa_index(if_index)
        .rtattrs(rt_attrs)
        .build()?;

    let rt_header = NlmsghdrBuilder::default()
        .nl_type(Rtm::Deladdr)
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_payload(NlPayload::Payload(rt_message))
        .build()?;

    socket.send(&rt_header).await?;
    socket.recv_all::<u16, Ifaddrmsg>().await?;
    Ok(())
}

async fn get_wireless_interfaces(
    links: &mut IndexMap<i32, LinkInterfaceInfo>,
) -> anyhow::Result<(Vec<WirelessRadioBss>, Vec<Ieee1905LocalInterface>)> {
    let (router, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty()).await?;
    let nl80211_family = router.resolve_genl_family(NL80211_GENL_NAME).await?;

    let interfaces = call_nl80211_get_interfaces(&router, nl80211_family).await?;
    let phy_map = call_nl80211_get_wiphy(&router, nl80211_family).await?;
    let radios = build_wireless_radios(&phy_map, &interfaces);

    let mut result = Vec::new();
    for interface in interfaces {
        let if_name = interface.if_name;
        let if_index = interface.if_index;
        let phy_index = interface.phy_index;

        let Some(link) = links.swap_remove(&if_index) else {
            warn!(if_name, if_index, "failed to find link info");
            continue;
        };
        let Some(phy) = phy_map.get(&phy_index) else {
            warn!(if_name, if_index, phy_index, "failed to find phy into");
            continue;
        };

        let station_info = call_nl80211_get_station(&router, nl80211_family, if_index)
            .await
            .inspect_err(|e| warn!(if_name, if_index, %e, "failed to get wireless station"))
            .unwrap_or_default();

        let survey_info = call_nl80211_get_survey(&router, nl80211_family, if_index)
            .await
            .inspect_err(|e| warn!(if_name, if_index, %e, "failed to get wireless survey"))
            .unwrap_or_default();

        let media_type_extra = MediaTypeSpecialInfoWifi {
            bssid: station_info.bssid.unwrap_or(interface.mac),
            role: convert_if_type_to_role(interface.if_type, interface.frequency).unwrap_or(0),
            reserved: 0,
            ap_channel_band: convert_channel_width_to_band(interface.channel_width).unwrap_or(0),
            ap_channel_center_frequency_index1: interface.center_freq_index1.unwrap_or(0),
            ap_channel_center_frequency_index2: interface.center_freq_index2.unwrap_or(0),
        };

        let local_interface_data = Ieee1905InterfaceData {
            mac: interface.mac,
            media_type: get_wireless_media_type(interface.frequency, phy),
            media_type_extra: MediaTypeSpecialInfo::Wifi(media_type_extra),
            bridging_flag: link.bridge_if_index.is_some(),
            bridging_tuple: link.bridge_if_index,
            vlan: link.vlan_id,
            metric: None,
            phy_rate: station_info.phy_rate,
            link_availability: survey_info.link_availability,
            signal_strength_dbm: station_info.signal_strength_dbm,
            ieee1905_neighbors: None,
            non_ieee1905_neighbors: Some(link.neighbours.iter().copied().collect()),
        };

        let local_interface = Ieee1905LocalInterface {
            name: link.if_name.clone(),
            index: link.if_index,
            flags: link.if_flags,
            link_stats: link.link_stats,
            data: local_interface_data,
        };
        result.push(local_interface);
    }
    Ok((radios, result))
}

fn build_wireless_radios(
    phy_map: &IndexMap<u32, WirelessPhyInfo>,
    interfaces: &[WirelessInterfaceInfo],
) -> Vec<WirelessRadioBss> {
    // group operational AP BSSes by phy + frequency
    let mut radios = IndexMap::<(u32, u32), WirelessRadioBss>::new();
    for interface in interfaces.iter() {
        if interface.if_type != Some(Nl80211IfType::Ap)
            || interface.frequency == 0
            || !interface.mlo_links.is_empty()
        {
            continue;
        }
        radios
            .entry((interface.phy_index, interface.frequency))
            .or_default()
            .bss_list
            .push(WirelessBssInfo {
                if_name: interface.if_name.clone(),
                bssid: interface.mac,
                ssid: interface.ssid.clone().unwrap_or_default(),
            });
    }

    // collect MLD mlo_link interfaces
    for interface in interfaces.iter() {
        if interface.if_type != Some(Nl80211IfType::Ap) {
            continue;
        }
        for mlo_link in interface.mlo_links.iter() {
            let radio = radios
                .entry((interface.phy_index, mlo_link.frequency))
                .or_default();

            radio.radio_unique_id = mlo_link.mac;
            radio.bss_list.push(WirelessBssInfo {
                if_name: interface.if_name.clone(),
                bssid: mlo_link.mac,
                ssid: interface.ssid.clone().unwrap_or_default(),
            });
        }
    }

    // count how many radios each phy contains
    let mut radios_per_phy = IndexMap::<u32, usize>::new();
    for (phy_index, _freq) in radios.keys() {
        *radios_per_phy.entry(*phy_index).or_default() += 1;
    }

    // helper closure to find wifi interface parent radio by name (wifi0.1 -> wifi0)
    let find_parent_wifi_radio_mac = |if_name: &str| {
        let interface = interfaces.iter().find(|interface| {
            if_name
                .strip_prefix(&interface.if_name)
                .and_then(|e| e.chars().next())
                .is_some_and(|e| !e.is_ascii_alphanumeric())
        })?;
        Some(interface.mac)
    };

    // helper closure to get radio uid from phy when only one radio-per-phy is present
    let find_radio_uid_from_phy = |phy_index: u32| {
        if radios_per_phy.get(&phy_index).copied() != Some(1) {
            return None;
        }
        phy_map.get(&phy_index).and_then(|phy| phy.perm_addr)
    };

    // building final BSS configuration collection
    let mut result = Vec::new();
    for ((phy_index, _frequency), mut radio) in radios {
        let Some(bss0) = radio.bss_list.first() else {
            continue;
        };

        if radio.radio_unique_id.is_zero() {
            radio.radio_unique_id = find_radio_uid_from_phy(phy_index)
                .or_else(|| {
                    let list = radio.bss_list.iter();
                    list.filter_map(|e| find_parent_wifi_radio_mac(&e.if_name))
                        .next()
                })
                .or_else(|| radio.bss_list.iter().map(|e| e.bssid).min())
                .unwrap_or(bss0.bssid);
        }

        radio.bss_list.sort_by_key(|e| e.bssid);
        result.push(radio);
    }

    result.sort_by_key(|e| e.radio_unique_id);
    result
}

#[derive(Debug)]
struct WirelessInterfaceInfo {
    mac: MacAddr,
    phy_index: u32,
    if_index: i32,
    if_name: String,
    if_type: Option<Nl80211IfType>,
    ssid: Option<Vec<u8>>,
    mlo_links: Vec<WirelessInterfaceMloLink>,
    frequency: u32,
    channel_width: Option<Nl80211ChannelWidth>,
    center_freq_index1: Option<u8>,
    center_freq_index2: Option<u8>,
}

#[derive(Debug)]
struct WirelessInterfaceMloLink {
    mac: MacAddr,
    frequency: u32,
}

async fn call_nl80211_get_interfaces(
    router: &NlRouter,
    family_id: u16,
) -> anyhow::Result<Vec<WirelessInterfaceInfo>> {
    let nl_message_attrs = NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(Nl80211Attribute::IfName)
                .build()?,
        )
        .nla_payload(())
        .build()?;

    let nl_message = GenlmsghdrBuilder::default()
        .cmd(Nl80211Command::GetInterface)
        .attrs(GenlBuffer::from_iter([nl_message_attrs]))
        .version(1)
        .build()?;

    let mut recv = router
        .send::<_, _, GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>(
            family_id,
            NlmF::DUMP | NlmF::ACK,
            NlPayload::Payload(nl_message),
        )
        .await?;

    let mut interfaces = Vec::new();
    while let Some(message) = recv.next().await {
        let message: Nlmsghdr<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>> = message?;
        let Some(payload) = message.get_payload() else {
            continue;
        };

        let handle = payload.attrs().get_attr_handle();
        let Ok(mac) = handle.get_attr_payload_as::<[u8; 6]>(Nl80211Attribute::Mac) else {
            continue;
        };
        let Ok(phy_index) = handle.get_attr_payload_as(Nl80211Attribute::Wiphy) else {
            continue;
        };
        let Ok(if_index) = handle.get_attr_payload_as(Nl80211Attribute::IfIndex) else {
            continue;
        };
        let Ok(if_name) = handle.get_attr_payload_as_with_len(Nl80211Attribute::IfName) else {
            continue;
        };

        let if_type = handle.get_attr_payload_as(Nl80211Attribute::IfType).ok();
        let ssid = handle.get_attr_payload_as_with_len(Nl80211Attribute::Ssid);
        let frequency = handle.get_attr_payload_as(Nl80211Attribute::WiphyFreq);
        let channel_width = handle.get_attr_payload_as(Nl80211Attribute::ChannelWidth);
        let center_freq1 = handle.get_attr_payload_as(Nl80211Attribute::CenterFreq1);
        let center_freq2 = handle.get_attr_payload_as(Nl80211Attribute::CenterFreq2);

        let mut mlo_links = Vec::new();
        if let Ok(links) = handle.get_nested_attributes::<u16>(Nl80211Attribute::MloLinks) {
            for link in links.iter() {
                let Ok(link_handle) = link.get_attr_handle::<Nl80211Attribute>() else {
                    continue;
                };

                let link_mac = link_handle.get_attr_payload_as::<[u8; 6]>(Nl80211Attribute::Mac);
                let link_frequency = link_handle.get_attr_payload_as(Nl80211Attribute::WiphyFreq);

                mlo_links.push(WirelessInterfaceMloLink {
                    mac: link_mac.unwrap_or_default().into(),
                    frequency: link_frequency.unwrap_or(0),
                });
            }
        }

        interfaces.push(WirelessInterfaceInfo {
            mac: MacAddr::from(mac),
            phy_index,
            if_index,
            if_name,
            if_type,
            ssid: ssid.ok(),
            mlo_links,
            frequency: frequency.unwrap_or(0),
            channel_width: channel_width.ok(),
            center_freq_index1: center_freq1.ok().and_then(get_wifi_center_frequency_index),
            center_freq_index2: center_freq2.ok().and_then(get_wifi_center_frequency_index),
        });
    }
    Ok(interfaces)
}

#[derive(Default)]
struct WirelessStationInfo {
    bssid: Option<MacAddr>,
    phy_rate: Option<u64>,
    signal_strength_dbm: Option<i8>,
}

async fn call_nl80211_get_station(
    router: &NlRouter,
    family_id: u16,
    if_index: i32,
) -> anyhow::Result<WirelessStationInfo> {
    let nl_attrs = NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(Nl80211Attribute::IfIndex)
                .build()?,
        )
        .nla_payload(if_index)
        .build()?;

    let nl_message = GenlmsghdrBuilder::default()
        .cmd(Nl80211Command::GetStation)
        .attrs(GenlBuffer::from_iter([nl_attrs]))
        .version(1)
        .build()?;

    let mut recv = router
        .send::<_, _, GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>(
            family_id,
            NlmF::DUMP | NlmF::ACK,
            NlPayload::Payload(nl_message),
        )
        .await?;

    let mut result = WirelessStationInfo::default();
    while let Some(message) = recv.next().await {
        let message: Nlmsghdr<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>> = message?;
        let Some(payload) = message.get_payload() else {
            continue;
        };

        let handle = payload.attrs().get_attr_handle();
        result.bssid = handle
            .get_attr_payload_as::<[u8; 6]>(Nl80211Attribute::Mac)
            .ok()
            .map(MacAddr::from);

        if let Ok(sta_info) = handle.get_nested_attributes(Nl80211Attribute::StaInfo) {
            if let Ok(rate_info) = sta_info.get_nested_attributes(Nl80211StaInfo::TxBitrate) {
                result.phy_rate = get_station_bitrate_bps(&rate_info);
            }
            result.signal_strength_dbm = get_signal_strength(&sta_info);
        }
    }
    Ok(result)
}

#[derive(Default)]
struct WirelessSurveyInfo {
    link_availability: Option<u8>,
}

async fn call_nl80211_get_survey(
    router: &NlRouter,
    family_id: u16,
    if_index: i32,
) -> anyhow::Result<WirelessSurveyInfo> {
    let nl_attrs = NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(Nl80211Attribute::IfIndex)
                .build()?,
        )
        .nla_payload(if_index)
        .build()?;

    let nl_message = GenlmsghdrBuilder::default()
        .cmd(Nl80211Command::GetSurvey)
        .attrs(GenlBuffer::from_iter([nl_attrs]))
        .version(1)
        .build()?;

    let mut recv = router
        .send::<_, _, GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>(
            family_id,
            NlmF::DUMP | NlmF::ACK,
            NlPayload::Payload(nl_message),
        )
        .await?;

    let mut result = WirelessSurveyInfo::default();
    while let Some(message) = recv.next().await {
        let message: Nlmsghdr<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>> = message?;
        let Some(payload) = message.get_payload() else {
            continue;
        };

        let handle = payload.attrs().get_attr_handle();
        if let Ok(info) = handle.get_nested_attributes(Nl80211Attribute::SurveyInfo) {
            result.link_availability = get_link_availability(&info);
        }
    }
    Ok(result)
}

#[derive(Debug, Default)]
struct WirelessPhyInfo {
    perm_addr: Option<MacAddr>,
    bands: IndexMap<Nl80211Band, WirelessPhyBand>,
}

#[derive(Debug, Default)]
struct WirelessPhyBand {
    max_bitrate: u64,
    is_ht: bool,
    is_vht: bool,
    is_he: bool,
    is_eht: bool,
}

async fn call_nl80211_get_wiphy(
    router: &NlRouter,
    family_id: u16,
) -> anyhow::Result<IndexMap<u32, WirelessPhyInfo>> {
    let nl_attrs = NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(Nl80211Attribute::SplitWiphyDump)
                .build()?,
        )
        .nla_payload(())
        .build()?;

    let nl_message = GenlmsghdrBuilder::<_, Nl80211Attribute>::default()
        .cmd(Nl80211Command::GetWiphy)
        .attrs(GenlBuffer::from_iter([nl_attrs]))
        .version(1)
        .build()?;

    let mut recv = router
        .send::<_, _, GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>(
            family_id,
            NlmF::DUMP | NlmF::REQUEST | NlmF::ACK,
            NlPayload::Payload(nl_message),
        )
        .await?;

    let mut result = IndexMap::new();
    while let Some(message) = recv.next().await {
        let message: Nlmsghdr<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>> = message?;
        let Some(payload) = message.get_payload() else {
            continue;
        };

        let handle = payload.attrs().get_attr_handle();
        let index = handle.get_attr_payload_as::<u32>(Nl80211Attribute::Wiphy)?;
        let phy = result.entry(index).or_insert_with(WirelessPhyInfo::default);

        // The wiphy permanent MAC (perm_addr) is reported as NL80211_ATTR_MAC in
        // the GetWiphy dump on Linux >= 5.4 (in any chunk of the split dump; the
        // kernel emits it unconditionally, so all-zero values must be skipped).
        if phy.perm_addr.is_none()
            && let Ok(mac) = handle.get_attr_payload_as::<[u8; 6]>(Nl80211Attribute::Mac)
            && let mac = MacAddr::from(mac)
            && mac != MacAddr::zero()
        {
            phy.perm_addr = Some(mac);
        }

        let bands = handle.get_nested_attributes::<Nl80211Band>(Nl80211Attribute::WiphyBands);
        for band in bands.ok().iter().flat_map(|e| e.iter()) {
            let phy_band = phy.bands.entry(*band.nla_type().nla_type()).or_default();
            let band_attr = band.get_attr_handle()?;

            phy_band.is_vht |= band_attr.get_attribute(Nl80211BandAttr::VhtCapa).is_some();
            phy_band.is_ht |= band_attr.get_attribute(Nl80211BandAttr::HtCapa).is_some();

            if let Some(data_list) = band_attr.get_attribute(Nl80211BandAttr::IfTypeData) {
                let data_list = data_list.get_attr_handle::<u16>()?;
                for data in data_list.iter() {
                    let data = data.get_attr_handle()?;
                    phy_band.is_eht |= data
                        .get_attribute(Nl80211BandIfTypeAttr::EhtCapPhy)
                        .is_some();

                    phy_band.is_he |= data
                        .get_attribute(Nl80211BandIfTypeAttr::HeCapPhy)
                        .is_some();
                }
            }

            if let Some(rates_list) = band_attr.get_attribute(Nl80211BandAttr::Rates) {
                let rates_list = rates_list.get_attr_handle::<u16>()?;
                for rates in rates_list.iter() {
                    let rates = rates.get_attr_handle()?;
                    if let Ok(rate) = rates.get_attr_payload_as::<u32>(Nl80211BitrateAttr::Rate) {
                        phy_band.max_bitrate = phy_band.max_bitrate.max(rate as u64 * 100_000);
                    }
                }
            }
        }
    }
    Ok(result)
}

async fn get_ethernet_interfaces(
    links: &IndexMap<i32, LinkInterfaceInfo>,
) -> anyhow::Result<Vec<Ieee1905LocalInterface>> {
    let interfaces = match call_eth_tool_get_link_modes().await {
        Ok(e) => e,
        Err(e) => {
            warn!(%e, "call_eth_tool_get_link_modes failed, falling back to netdev");
            call_netdev_get_ethernet_interfaces().await?
        }
    };

    let if_map: IndexMap<_, _> = interfaces.into_iter().map(|e| (e.if_index, e)).collect();

    let mut result = Vec::new();
    for link in links.values() {
        let if_index = link.if_index;
        let if_name = link.if_name.as_str();

        let Some(interface) = if_map.get(&if_index) else {
            warn!(if_name, if_index, "failed to find ethernet info");
            continue;
        };

        let phy_rate = interface.link_speed;
        let media_type =
            if interface.is_802_3ab_supported || phy_rate.is_some_and(|e| e >= 1_000_000_000) {
                MediaType::ETHERNET_802_3ab
            } else {
                MediaType::ETHERNET_802_3u
            };

        let local_interface_data = Ieee1905InterfaceData {
            mac: link.mac,
            media_type,
            media_type_extra: Default::default(),
            bridging_flag: link.bridge_if_index.is_some(),
            bridging_tuple: link.bridge_if_index,
            vlan: link.vlan_id,
            metric: None,
            phy_rate,
            link_availability: None,
            signal_strength_dbm: None,
            non_ieee1905_neighbors: Some(link.neighbours.iter().copied().collect()),
            ieee1905_neighbors: None,
        };

        let local_interface = Ieee1905LocalInterface {
            name: link.if_name.clone(),
            index: link.if_index,
            flags: link.if_flags,
            link_stats: link.link_stats,
            data: local_interface_data,
        };

        result.push(local_interface);
    }
    Ok(result)
}

#[derive(Debug)]
struct EthernetInterfaceInfo {
    if_index: i32,
    link_speed: Option<u64>,
    is_802_3ab_supported: bool,
}

async fn call_eth_tool_get_link_modes() -> anyhow::Result<Vec<EthernetInterfaceInfo>> {
    let (router, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty()).await?;
    let eth_tool_family_id = router.resolve_genl_family(ETH_TOOL_GENL_NAME).await?;

    let nl_attrs = NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(EthToolLinkModesAttribute::Header)
                .nla_nested(true)
                .build()?,
        )
        .nla_payload(())
        .build()?;

    let nl_message = GenlmsghdrBuilder::default()
        .cmd(EthToolMessage::LinkModesGet)
        .attrs(GenlBuffer::from_iter([nl_attrs]))
        .version(1)
        .build()?;

    let mut recv = router
        .send::<_, _, GenlId, Genlmsghdr<EthToolMessage, EthToolLinkModesAttribute>>(
            eth_tool_family_id,
            NlmF::DUMP | NlmF::ACK,
            NlPayload::Payload(nl_message),
        )
        .await?;

    let mut interfaces = Vec::new();
    while let Some(message) = recv.next().await {
        let message: Nlmsghdr<GenlId, Genlmsghdr<EthToolMessage, _>> = message?;
        let Some(payload) = message.get_payload() else {
            continue;
        };

        let handle = payload.attrs().get_attr_handle();
        let Ok(header) = handle.get_nested_attributes(EthToolLinkModesAttribute::Header) else {
            continue;
        };
        let Ok(if_index) = header.get_attr_payload_as(EthToolHeaderAttribute::DevIndex) else {
            continue;
        };

        let link_speed = handle
            .get_attr_payload_as::<u32>(EthToolLinkModesAttribute::Speed)
            .ok()
            .filter(|e| *e < u32::MAX) // returns u32::MAX when speed is not available
            .map(|e| u64::from(e) * 1_000_000);

        let mut is_802_3ab_supported = false;
        if let Ok(bitset_handle) = handle.get_nested_attributes(EthToolLinkModesAttribute::Ours) {
            let flags_802_3ab = [
                EthToolLinkMode::Mode1000baseT_Half_BIT as u32,
                EthToolLinkMode::Mode1000baseT_Full_BIT as u32,
            ];

            if let Ok(bits) = bitset_handle.get_nested_attributes::<u16>(EthToolBitsetAttr::Bits) {
                for bit in bits.iter() {
                    let bit = bit.get_attr_handle::<EthToolBitsetBitAttr>()?;
                    if let Ok(index) = bit.get_attr_payload_as(EthToolBitsetBitAttr::Index)
                        && flags_802_3ab.contains(&index)
                    {
                        is_802_3ab_supported = true;
                    }
                }
            }

            if let Ok(raw_bits) = bitset_handle
                .get_attr_payload_as_with_len_borrowed::<&[u8]>(EthToolBitsetAttr::Value)
            {
                let check_bitset = |mode: EthToolLinkMode| {
                    let value = mode as usize;
                    let bit_index = value / 8;
                    let bit_mask = 1 << (value % 8);
                    raw_bits.get(bit_index).unwrap_or(&0).bitand(bit_mask) != 0
                };

                is_802_3ab_supported |= check_bitset(EthToolLinkMode::Mode1000baseT_Half_BIT);
                is_802_3ab_supported |= check_bitset(EthToolLinkMode::Mode1000baseT_Full_BIT);
            }
        }

        interfaces.push(EthernetInterfaceInfo {
            if_index,
            link_speed,
            is_802_3ab_supported,
        });
    }
    Ok(interfaces)
}

async fn call_netdev_get_ethernet_interfaces() -> anyhow::Result<Vec<EthernetInterfaceInfo>> {
    const ETH_TYPES: [InterfaceType; 4] = [
        InterfaceType::Ethernet,
        InterfaceType::Ethernet3Megabit,
        InterfaceType::FastEthernetT,
        InterfaceType::GigabitEthernet,
    ];

    let mut result = Vec::new();
    for interface in tokio::task::spawn_blocking(netdev::get_interfaces).await? {
        if !ETH_TYPES.contains(&interface.if_type) {
            continue;
        }
        result.push(EthernetInterfaceInfo {
            if_index: interface.index as i32,
            link_speed: None,
            is_802_3ab_supported: true,
        });
    }
    Ok(result)
}

async fn call_ovs_interface_to_bridge(if_name: &str) -> anyhow::Result<String> {
    debug!("ovs-vsctl iface-to-br {if_name}");

    let output = tokio::process::Command::new("ovs-vsctl")
        .args(["--timeout=5", "--", "iface-to-br", if_name])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ovs-vsctl iface-to-br {if_name} failed: {stderr}");
    }

    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    debug!("ovs-vsctl iface-to-br {if_name} -> {result:?}");
    Ok(result)
}

async fn call_ovs_list_bridge_interfaces(bridge_name: &str) -> anyhow::Result<IndexSet<String>> {
    debug!("ovs-vsctl list-ifaces {bridge_name}");

    let output = tokio::process::Command::new("ovs-vsctl")
        .args(["--timeout=5", "--", "list-ifaces", bridge_name])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ovs-vsctl list-ifaces {bridge_name} failed: {stderr}");
    }

    let result = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();

    debug!("ovs-vsctl list-ifaces {bridge_name} -> {result:?}");
    Ok(result)
}

fn get_link_stats(handle: &RtAttrHandle<Ifla>) -> Option<RtnlLinkStats64> {
    if let Ok(stats) = handle.get_attr_payload_as_with_len_borrowed::<&[u8]>(Ifla::Stats64) {
        unsafe {
            return Some(std::ptr::read_unaligned(stats.as_ptr().cast()));
        }
    }
    if let Ok(stats) = handle.get_attr_payload_as_with_len_borrowed::<&[u8]>(Ifla::Stats) {
        unsafe {
            return Some(std::ptr::read_unaligned(stats.as_ptr().cast::<RtnlLinkStats>()).into());
        }
    }
    None
}

fn get_station_bitrate_bps(handle: &GenlAttrHandle<Nl80211RateInfo>) -> Option<u64> {
    if let Ok(bitrate) = handle.get_attr_payload_as::<u32>(Nl80211RateInfo::Bitrate32) {
        return Some(u64::from(bitrate) * 100_000);
    }
    if let Ok(bitrate) = handle.get_attr_payload_as::<u16>(Nl80211RateInfo::Bitrate) {
        return Some(u64::from(bitrate) * 100_000);
    }
    None
}

fn get_wireless_media_type(frequency: u32, phy: &WirelessPhyInfo) -> MediaType {
    if frequency > 57_000 {
        // 802.11ad
        return MediaType::WIRELESS_802_11ad_60;
    }

    let band = get_band_from_frequency(frequency).unwrap_or(Nl80211Band::Band2GHz);
    let Some(phy_band) = phy.bands.get(&band) else {
        return MediaType::default();
    };

    if phy_band.is_eht {
        // 802.11be
        return MediaType::WIRELESS_802_11be;
    }

    if phy_band.is_he {
        // 802.11ax
        return MediaType::WIRELESS_802_11ax;
    }

    if phy_band.is_vht {
        // 802.11ac
        return MediaType::WIRELESS_802_11ac_5;
    }

    if phy_band.is_ht {
        // 802.11n
        return if band == Nl80211Band::Band2GHz {
            MediaType::WIRELESS_802_11n_2_4
        } else {
            MediaType::WIRELESS_802_11n_5
        };
    }

    if band != Nl80211Band::Band2GHz {
        // 802.11a
        return MediaType::WIRELESS_802_11a_5;
    }

    if phy_band.max_bitrate > 11_000_000 {
        // 802.11b
        MediaType::WIRELESS_802_11b_2_4
    } else {
        // 802.11g
        MediaType::WIRELESS_802_11g_2_4
    }
}

fn get_link_availability(handle: &GenlAttrHandle<Nl80211SurveyInfoAttr>) -> Option<u8> {
    let Ok(total) = handle.get_attr_payload_as::<u64>(Nl80211SurveyInfoAttr::Time) else {
        return None;
    };
    let Ok(busy) = handle.get_attr_payload_as::<u64>(Nl80211SurveyInfoAttr::TimeBusy) else {
        return None;
    };
    Some((busy * 100).checked_div(total)?.clamp(0, 100) as u8)
}

fn get_signal_strength(handle: &GenlAttrHandle<Nl80211StaInfo>) -> Option<i8> {
    if let Ok(signal) = handle.get_attr_payload_as::<i8>(Nl80211StaInfo::Signal) {
        return Some(signal);
    }
    if let Ok(signal) = handle.get_attr_payload_as::<i8>(Nl80211StaInfo::SignalAvg) {
        return Some(signal);
    }
    None
}

fn get_band_from_frequency(frequency: u32) -> Option<Nl80211Band> {
    Some(match frequency {
        2_400..2_500 => Nl80211Band::Band2GHz,
        5_150..5_900 => Nl80211Band::Band5GHz,
        5_925..7_125 => Nl80211Band::Band6GHz,
        _ => return None,
    })
}

///
/// https://schupen.net/lib/wifi/802.11ac-2013.pdf
///
fn get_wifi_center_frequency_index(center_frequency: u32) -> Option<u8> {
    let starting_frequency = match get_band_from_frequency(center_frequency)? {
        Nl80211Band::Band2GHz => Some(2407),
        Nl80211Band::Band5GHz => Some(5000),
        Nl80211Band::Band6GHz => Some(5950),
        _ => None,
    };
    starting_frequency.map(|e| center_frequency.saturating_sub(e).div(5) as u8)
}

///
/// https://schupen.net/lib/wifi/802.11ac-2013.pdf
///
fn convert_channel_width_to_band(width: Option<Nl80211ChannelWidth>) -> Option<u8> {
    Some(match width? {
        Nl80211ChannelWidth::Width20NoHt => 0,
        Nl80211ChannelWidth::Width20 => 0,
        Nl80211ChannelWidth::Width40 => 1,
        Nl80211ChannelWidth::Width80 => 2,
        Nl80211ChannelWidth::Width160 => 3,
        Nl80211ChannelWidth::Width80p80 => 4,
        Nl80211ChannelWidth::Width320 => 5,
        _ => return None,
    })
}

///
/// https://schupen.net/lib/wifi/802.11ac-2013.pdf
///
/// “0000” – AP
/// “0001” – “0011” Reserved
/// “0100” – non-AP/non-PCP STA
/// “1000” – Wi-Fi P2P Client (see [B04])
/// “1001” – Wi-Fi P2P Group Owner (see [B04])
/// “1010” – 802.11adPCP
/// “1011” – “1111” Reserved
///
fn convert_if_type_to_role(if_type: Option<Nl80211IfType>, frequency: u32) -> Option<u8> {
    Some(match if_type? {
        Nl80211IfType::Station => {
            if frequency > 57_000 {
                MediaTypeSpecialInfoWifi::ROLE_802_11AD_PCP
            } else {
                MediaTypeSpecialInfoWifi::ROLE_NO_AD_NO_PCP_STATION
            }
        }
        Nl80211IfType::Ap => MediaTypeSpecialInfoWifi::ROLE_AP,
        Nl80211IfType::ApVlan => MediaTypeSpecialInfoWifi::ROLE_AP,
        Nl80211IfType::P2pClient => MediaTypeSpecialInfoWifi::ROLE_P2P_CLIENT,
        Nl80211IfType::P2pGo => MediaTypeSpecialInfoWifi::ROLE_P2P_GROUP_OWNER,
        _ => return None,
    })
}

pub fn convert_mac_to_eui64(mac: MacAddr) -> Ipv6Addr {
    Ipv6Addr::from([
        // prefix
        0xfe,
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // eui
        mac.0 ^ 0x02,
        mac.1,
        mac.2,
        0xff,
        0xfe,
        mac.3,
        mac.4,
        mac.5,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_link_availability() -> anyhow::Result<()> {
        let test_values: &[(u64, u64, Option<u8>)] = &[
            (0, 0, None),
            (0, 1, None),
            (1, 0, Some(0)),
            (100, 50, Some(50)),
            (1000, 300, Some(30)),
        ];

        for (total, busy, expected) in test_values {
            let attr_time = NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(Nl80211SurveyInfoAttr::Time)
                        .build()?,
                )
                .nla_payload(*total)
                .build()?;

            let attr_busy = NlattrBuilder::default()
                .nla_type(
                    AttrTypeBuilder::default()
                        .nla_type(Nl80211SurveyInfoAttr::TimeBusy)
                        .build()?,
                )
                .nla_payload(*busy)
                .build()?;

            let buffer = GenlBuffer::from_iter([attr_time, attr_busy]);
            let handle = GenlAttrHandle::new(buffer);

            let actual = get_link_availability(&handle);
            assert_eq!(actual, *expected, "input: total = {total}, busy = {busy}");
        }
        Ok(())
    }

    #[test]
    fn test_convert_mac_to_eui64() {
        let mac = MacAddr::from([0x9e, 0x7f, 0x24, 0x2b, 0x41, 0x86]);
        let actual = convert_mac_to_eui64(mac);
        let expected = Ipv6Addr::from_bits(0xfe800000000000009c7f24fffe2b4186u128);
        assert_eq!(actual, expected);
    }
}
