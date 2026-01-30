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

use std::collections::HashSet;
// External crates
use pnet::datalink::{self, MacAddr};

// Standard library
use crate::cmdu_codec::{MediaType, MediaTypeSpecialInfo, MediaTypeSpecialInfoWifi};
use crate::linux::eth_tool::{
    EthToolHeaderAttribute, EthToolLinkModesAttribute, EthToolMessage, ETH_TOOL_GENL_NAME,
};
use crate::linux::if_link::{RtnlLinkStats, RtnlLinkStats64};
use crate::linux::nl80211::{
    Nl80211Attribute, Nl80211ChannelWidth, Nl80211Command, Nl80211IfType, Nl80211RateInfo,
    Nl80211StaInfo, Nl80211SurveyInfoAttr, NL80211_GENL_NAME,
};
use crate::topology_manager::{Ieee1905InterfaceData, Ieee1905LocalInterface};
use indexmap::IndexMap;
use neli::attr::Attribute;
use neli::consts::nl::{GenlId, NlmF};
use neli::consts::rtnl::{Arphrd, Iff, Ifla, IflaInfo, IflaVlan, RtAddrFamily, Rtm};
use neli::consts::socket::NlFamily;
use neli::genl::{AttrTypeBuilder, GenlAttrHandle, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::router::asynchronous::{NlRouter, NlRouterReceiverHandle};
use neli::rtnl::{Ifinfomsg, IfinfomsgBuilder, RtAttrHandle};
use neli::types::GenlBuffer;
use neli::utils::Groups;
use std::fs;
use std::ops::Div;
use std::process::Command;
use tracing::warn;

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

pub fn get_forwarding_interface_mac(interface_name: String) -> Option<MacAddr> {
    // Fetch all network interfaces
    let interfaces = datalink::interfaces();

    // Find the first Ethernet interface (`ethX`)
    if let Some(mac_addr) = interfaces
        .iter()
        .find(|iface| iface.name.starts_with(&interface_name))
        .and_then(|iface| iface.mac)
    // Extract and return MAC address if found
    {
        tracing::debug!("Ethernet interface found for forwarding {mac_addr}");
        Some(mac_addr)
    } else {
        tracing::debug!("No Ethernet interface found for forwarding, using default.");
        Some(MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
    }
}

/// **Returns `Some(String)` if found, otherwise `None`.**
pub fn get_forwarding_interface_name(interface_name: String) -> Option<String> {
    // Fetch all network interfaces
    let interfaces = datalink::interfaces();

    // Find the first Ethernet interface (`ethX`) and return its name
    interfaces
        .iter()
        .find(|iface| iface.name.starts_with(&interface_name))
        .map(|iface| iface.name.clone()) // Extract and return interface name
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

pub fn is_bridge_member(interface_name: &str) -> bool {
    let path = format!("/sys/class/net/{}/brport", interface_name);
    fs::metadata(&path).is_ok() // If this directory exists, it's part of a bridge
}

/// Retrieves VLAN ID from `/proc/net/vlan/config`
pub fn get_vlan_id(interface_name: &str) -> Option<u16> {
    let contents = fs::read_to_string("/proc/net/vlan/config").ok()?;
    for line in contents.lines().skip(2) {
        // Skip headers
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == interface_name {
            return parts[1].parse().ok();
        }
    }
    None
}

/// Fetches MAC addresses learned on a bridge interface.
/// Gets MAC addresses of neighbors on a **specific** interface.
pub fn get_neighbor_macs(interface_name: &str) -> Vec<MacAddr> {
    let mut mac_addresses = HashSet::new(); // Use HashSet to avoid duplicates

    // Run `ip neigh show dev <interface_name>` to list neighbors **only** for the given interface
    let output = Command::new("ip")
        .arg("neigh")
        .arg("show")
        .arg("dev")
        .arg(interface_name) // Now filters by specific interface
        .output();

    if let Ok(output) = output {
        if let Ok(stdout) = str::from_utf8(&output.stdout) {
            // Convert raw output to string
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 && parts.contains(&"lladdr") {
                    if let Some(mac_index) = parts.iter().position(|&x| x == "lladdr") {
                        if mac_index + 1 < parts.len() {
                            if let Ok(parsed_mac) = parse_mac(parts[mac_index + 1]) {
                                mac_addresses.insert(parsed_mac);
                            }
                        }
                    }
                }
            }
        }
    } else {
        eprintln!("Failed to execute 'ip neigh show dev {}'", interface_name);
    }

    mac_addresses.into_iter().collect() // Convert HashSet to Vec
}

/// Helper function to parse a MAC address from a string
fn parse_mac(mac_str: &str) -> Result<MacAddr, ()> {
    let bytes: Vec<u8> = mac_str
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();

    if bytes.len() == 6 {
        Ok(MacAddr::new(
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        ))
    } else {
        Err(())
    }
}

pub async fn get_interfaces() -> anyhow::Result<Vec<Ieee1905LocalInterface>> {
    let mut interfaces = IndexMap::new();
    for ethernet in get_all_interfaces().await? {
        let data = Ieee1905InterfaceData {
            mac: ethernet.mac,
            media_type: MediaType::ETHERNET_802_3ab,
            media_type_extra: Default::default(),
            bridging_flag: ethernet.bridge_if_index.is_some(),
            bridging_tuple: ethernet.bridge_if_index,
            vlan: ethernet.vlan_id,
            metric: None,
            phy_rate: Some(1_000_000),
            link_availability: None,
            signal_strength_dbm: None,
            non_ieee1905_neighbors: None,
            ieee1905_neighbors: None,
        };
        let interface = Ieee1905LocalInterface {
            name: ethernet.if_name.clone(),
            index: ethernet.if_index,
            flags: ethernet.if_flags,
            link_stats: ethernet.link_stats,
            data,
        };
        interfaces.insert(ethernet.if_index, (interface, ethernet));
    }
    for info in get_wireless_interfaces().await.unwrap_or_default() {
        let Some((interface, ethernet)) = interfaces.get_mut(&info.if_index) else {
            warn!(
                if_index = info.if_index,
                if_name = info.if_name,
                mac_addr = %info.mac,
                "interface not found (wireless)",
            );
            continue;
        };
        if info.mac != ethernet.mac {
            warn!(
                if_index = ethernet.if_index,
                if_name_w = info.if_name,
                if_name_e = ethernet.if_name,
                addr_w = %info.mac,
                addr_e = %ethernet.mac,
                "wireless and ethernet interfaces have different mac",
            );
            continue;
        }
        interface.data.phy_rate = Some(info.phy_rate);
        interface.data.link_availability = info.link_availability;
        interface.data.signal_strength_dbm = info.signal_strength_dbm;
        interface.data.media_type = info.media_type;
        interface.data.media_type_extra = MediaTypeSpecialInfo::Wifi(MediaTypeSpecialInfoWifi {
            bssid: info.bssid.unwrap_or_default(),
            role: convert_if_type_to_role(info.if_type, info.frequency).unwrap_or_default(),
            reserved: 0,
            ap_channel_band: convert_channel_width_to_band(info.channel_width).unwrap_or_default(),
            ap_channel_center_frequency_index1: info.center_freq_index1.unwrap_or_default(),
            ap_channel_center_frequency_index2: info.center_freq_index2.unwrap_or_default(),
        });
    }
    for info in get_lan_interfaces().await.unwrap_or_default() {
        let Some((interface, _)) = interfaces.get_mut(&info.if_index) else {
            warn!(
                if_index = info.if_index,
                if_name = info.if_name,
                "interface not found (ethernet)",
            );
            continue;
        };
        interface.data.phy_rate = info.link_speed;
    }
    Ok(interfaces.into_values().map(|e| e.0).collect())
}

#[derive(Debug)]
struct LinkEthernetInfo {
    mac: MacAddr,
    if_index: i32,
    if_name: String,
    if_flags: Iff,
    bridge_if_index: Option<u32>,
    vlan_id: Option<u16>,
    link_stats: Option<RtnlLinkStats64>,
}

async fn get_all_interfaces() -> anyhow::Result<Vec<LinkEthernetInfo>> {
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

    let mut interfaces = Vec::new();
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

        fn get_vlan_id(handle: &RtAttrHandle<Ifla>) -> Option<u16> {
            let link_info = handle
                .get_nested_attributes::<IflaInfo>(Ifla::Linkinfo)
                .ok()?;
            let kind = link_info
                .get_attr_payload_as_with_len_borrowed::<&[u8]>(IflaInfo::Kind)
                .ok()?;
            if kind == b"vlan\0" {
                let data = link_info
                    .get_nested_attributes::<IflaVlan>(IflaInfo::Data)
                    .ok()?;
                return data.get_attr_payload_as(IflaVlan::Id).ok();
            }
            None
        }

        let if_flags = *payload.ifi_flags();
        let if_index = i32::from(*payload.ifi_index());
        let vlan_id = get_vlan_id(&attr_handle);
        let bridge_if_index = attr_handle.get_attr_payload_as(Ifla::Master).ok();
        let link_stats = get_link_stats(&attr_handle);

        interfaces.push(LinkEthernetInfo {
            mac: MacAddr::from(mac),
            if_index,
            if_name,
            if_flags,
            bridge_if_index,
            vlan_id,
            link_stats,
        });
    }

    Ok(interfaces)
}

#[derive(Debug)]
struct WirelessInterfaceInfo {
    mac: MacAddr,
    bssid: Option<MacAddr>,
    if_index: i32,
    if_name: String,
    if_type: Option<Nl80211IfType>,
    phy_rate: u64,
    frequency: u32,
    channel_width: Option<Nl80211ChannelWidth>,
    center_freq_index1: Option<u8>,
    center_freq_index2: Option<u8>,
    link_availability: Option<u8>,
    signal_strength_dbm: Option<i8>,
    media_type: MediaType,
}

async fn get_wireless_interfaces() -> anyhow::Result<Vec<WirelessInterfaceInfo>> {
    let (router, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty()).await?;
    let nl80211_family_id = router.resolve_genl_family(NL80211_GENL_NAME).await?;

    let mut interfaces = call_nl80211_get_interfaces(&router, nl80211_family_id).await?;
    for interface in interfaces.iter_mut() {
        if let Err(e) = call_nl80211_get_station(&router, nl80211_family_id, interface).await {
            warn!(
                if_name = interface.if_name,
                if_index = interface.if_index,
                %e,
                "failed to get wireless station",
            );
        }
        if let Err(e) = call_nl80211_get_survey(&router, nl80211_family_id, interface).await {
            warn!(
                if_name = interface.if_name,
                if_index = interface.if_index,
                %e,
                "failed to get wireless survey",
            );
        }
    }
    Ok(interfaces)
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
        let Ok(if_index) = handle.get_attr_payload_as(Nl80211Attribute::IfIndex) else {
            continue;
        };
        let Ok(if_name) = handle.get_attr_payload_as_with_len(Nl80211Attribute::IfName) else {
            continue;
        };
        let Ok(frequency) = handle.get_attr_payload_as(Nl80211Attribute::WiphyFreq) else {
            continue;
        };

        let if_type = handle.get_attr_payload_as(Nl80211Attribute::IfType).ok();
        let channel_width = handle
            .get_attr_payload_as(Nl80211Attribute::ChannelWidth)
            .ok();
        let center_freq1 = handle
            .get_attr_payload_as(Nl80211Attribute::CenterFreq1)
            .ok();
        let center_freq2 = handle
            .get_attr_payload_as(Nl80211Attribute::CenterFreq2)
            .ok();

        interfaces.push(WirelessInterfaceInfo {
            mac: MacAddr::from(mac),
            bssid: None,
            if_index,
            if_name,
            if_type,
            phy_rate: 1_000_000,
            frequency,
            channel_width,
            center_freq_index1: center_freq1.and_then(get_wifi_center_frequency_index),
            center_freq_index2: center_freq2.and_then(get_wifi_center_frequency_index),
            link_availability: None,
            signal_strength_dbm: None,
            media_type: MediaType::WIRELESS_802_11b_2_4,
        });
    }
    Ok(interfaces)
}

async fn call_nl80211_get_station(
    router: &NlRouter,
    family_id: u16,
    interface: &mut WirelessInterfaceInfo,
) -> anyhow::Result<()> {
    let nl_attrs = NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(Nl80211Attribute::IfIndex)
                .build()?,
        )
        .nla_payload(interface.if_index)
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

    while let Some(message) = recv
        .next::<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>()
        .await
    {
        let message = message?;
        let Some(payload) = message.get_payload() else {
            continue;
        };

        let handle = payload.attrs().get_attr_handle();
        interface.bssid = handle
            .get_attr_payload_as::<[u8; 6]>(Nl80211Attribute::Mac)
            .ok()
            .map(MacAddr::from);

        if let Ok(sta_info) = handle.get_nested_attributes(Nl80211Attribute::StaInfo) {
            if let Ok(rate_info) = sta_info.get_nested_attributes(Nl80211StaInfo::TxBitrate) {
                let bitrate = get_station_bitrate_bps(&rate_info).unwrap_or_default();
                interface.phy_rate = bitrate;
                interface.media_type =
                    get_wireless_media_type(interface.frequency, interface.phy_rate, &rate_info);
            }
            if let Some(signal) = get_signal_strength(&sta_info) {
                interface.signal_strength_dbm = Some(signal);
            }
        }
    }
    Ok(())
}

async fn call_nl80211_get_survey(
    router: &NlRouter,
    family_id: u16,
    interface: &mut WirelessInterfaceInfo,
) -> anyhow::Result<()> {
    let nl_attrs = NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(Nl80211Attribute::IfIndex)
                .build()?,
        )
        .nla_payload(interface.if_index)
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

    while let Some(message) = recv
        .next::<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>>()
        .await
    {
        let message = message?;
        let Some(payload) = message.get_payload() else {
            continue;
        };

        let handle = payload.attrs().get_attr_handle();
        let Ok(info) = handle.get_nested_attributes(Nl80211Attribute::SurveyInfo) else {
            continue;
        };

        if let Some(link_availability) = get_link_availability(&info) {
            interface.link_availability = Some(link_availability);
        }
    }
    Ok(())
}

#[derive(Debug)]
struct EthernetInterfaceInfo {
    if_index: i32,
    if_name: String,
    link_speed: Option<u64>,
}

async fn get_lan_interfaces() -> anyhow::Result<Vec<EthernetInterfaceInfo>> {
    let (router, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty()).await?;
    let eth_tool_family_id = router.resolve_genl_family(ETH_TOOL_GENL_NAME).await?;

    call_eth_tool_get_link_modes(&router, eth_tool_family_id).await
}

async fn call_eth_tool_get_link_modes(
    router: &NlRouter,
    family_id: u16,
) -> anyhow::Result<Vec<EthernetInterfaceInfo>> {
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
            family_id,
            NlmF::DUMP | NlmF::ACK,
            NlPayload::Payload(nl_message),
        )
        .await?;

    let mut interfaces = Vec::new();
    while let Some(message) = recv
        .next::<GenlId, Genlmsghdr<EthToolMessage, EthToolLinkModesAttribute>>()
        .await
    {
        let message = message?;
        let Some(payload) = message.get_payload() else {
            continue;
        };

        let handle = payload.attrs().get_attr_handle();
        let Some(header) = handle.get_attribute(EthToolLinkModesAttribute::Header) else {
            continue;
        };
        let Ok(header_handle) = header.get_attr_handle() else {
            continue;
        };
        let Some(if_index) = header_handle.get_attribute(EthToolHeaderAttribute::DevIndex) else {
            continue;
        };
        let Ok(if_index) = if_index.get_payload_as::<i32>() else {
            continue;
        };
        let Some(if_name) = header_handle.get_attribute(EthToolHeaderAttribute::DevName) else {
            continue;
        };
        let Ok(if_name) = if_name.get_payload_as_with_len::<String>() else {
            continue;
        };

        let link_speed = handle
            .get_attr_payload_as::<u32>(EthToolLinkModesAttribute::Speed)
            .ok()
            .filter(|e| *e < u32::MAX) // returns u32::MAX when speed is not available
            .map(|e| u64::from(e) * 1_000_000);

        interfaces.push(EthernetInterfaceInfo {
            if_index,
            if_name,
            link_speed,
        });
    }
    Ok(interfaces)
}

fn get_link_stats(handle: &RtAttrHandle<Ifla>) -> Option<RtnlLinkStats64> {
    if let Ok(stats) = handle.get_attr_payload_as_with_len_borrowed::<&[u8]>(Ifla::Stats64) {
        debug_assert_eq!(stats.len(), size_of::<RtnlLinkStats64>());
        unsafe {
            return Some(std::ptr::read_unaligned(stats.as_ptr().cast()));
        }
    }
    if let Ok(stats) = handle.get_attr_payload_as_with_len_borrowed::<&[u8]>(Ifla::Stats) {
        debug_assert_eq!(stats.len(), size_of::<RtnlLinkStats>());
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

fn get_wireless_media_type(
    frequency: u32,
    bitrate: u64,
    rate_info: &GenlAttrHandle<Nl80211RateInfo>,
) -> MediaType {
    let is_2_4 = frequency < 3000;

    if frequency > 57_000 {
        // 802.11ad
        return MediaType::WIRELESS_802_11ad_60;
    }

    if rate_info.get_attribute(Nl80211RateInfo::EhtMcs).is_some() {
        // 802.11be
        return MediaType::WIRELESS_802_11be;
    }

    if rate_info.get_attribute(Nl80211RateInfo::HeMcs).is_some() {
        // 802.11ax
        return MediaType::WIRELESS_802_11ax;
    }

    if rate_info.get_attribute(Nl80211RateInfo::VhtMcs).is_some() {
        // 802.11ac
        return MediaType::WIRELESS_802_11ac_5;
    }

    if rate_info.get_attribute(Nl80211RateInfo::Mcs).is_some() {
        // 802.11n
        return if is_2_4 {
            MediaType::WIRELESS_802_11n_2_4
        } else {
            MediaType::WIRELESS_802_11n_5
        };
    }

    // 802.11a
    if !is_2_4 {
        return MediaType::WIRELESS_802_11a_5;
    }

    if bitrate > 11_000_000 {
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

///
/// https://schupen.net/lib/wifi/802.11ac-2013.pdf
///
fn get_wifi_center_frequency_index(center_frequency: u32) -> Option<u8> {
    let starting_frequency = match center_frequency {
        2_400..2_500 => Some(2407),
        5_150..5_900 => Some(5000),
        5_925..7_125 => Some(5950),
        _ => None,
    };
    starting_frequency.map(|e| center_frequency.saturating_sub(e).div(5) as u8)
}

///
/// https://schupen.net/lib/wifi/802.11ac-2013.pdf
///
/// Set to 0 for 20 MHz or 40 MHz operating channel width.
/// Set to 1 for 80 MHz operating channel width.
/// Set to 2 for 160 MHz operating channel width.
/// Set to 3 for 80+80 MHz operating channel width.
/// Values in the range 4 to 255 are reserved.
///
fn convert_channel_width_to_band(width: Option<Nl80211ChannelWidth>) -> Option<u8> {
    Some(match width? {
        Nl80211ChannelWidth::Width20NoHt => 0,
        Nl80211ChannelWidth::Width20 => 0,
        Nl80211ChannelWidth::Width40 => 0,
        Nl80211ChannelWidth::Width80 => 1,
        Nl80211ChannelWidth::Width80p80 => 3,
        Nl80211ChannelWidth::Width160 => 2,
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
                0b1010
            } else {
                0b0100
            }
        }
        Nl80211IfType::Ap => 0b0000,
        Nl80211IfType::ApVlan => 0b0000,
        Nl80211IfType::P2pClient => 0b1000,
        Nl80211IfType::P2pGo => 0b1001,
        _ => return None,
    })
}
