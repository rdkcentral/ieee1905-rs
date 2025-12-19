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
use std::fs;
use std::ops::Div;
use std::process::Command;
use indexmap::{IndexMap};
use neli::consts::nl::{GenlId, NlmF};
use neli::consts::rtnl::{Arphrd, Ifla, IflaInfo, IflaVlan, RtAddrFamily, Rtm};
use neli::consts::socket::NlFamily;
use neli::genl::{AttrTypeBuilder, GenlAttrHandle, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder, NoUserHeader};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::router::asynchronous::{NlRouter, NlRouterReceiverHandle};
use neli::rtnl::{Ifinfomsg, IfinfomsgBuilder};
use neli::types::GenlBuffer;
use neli::utils::Groups;
use netdev::interface::types::InterfaceType;
use tracing::warn;
use crate::cmdu_codec::MediaType;
use crate::linux::if_link::{RtnlLinkStats, RtnlLinkStats64};
use crate::linux::nl80211::{Nl80211Attribute, Nl80211ChannelWidth, Nl80211Command, Nl80211RateInfo, Nl80211StaInfo, NL80211_GENL_NAME};
use crate::topology_manager::Ieee1905InterfaceData;

pub struct InterfaceInfo {
    pub name: String,
    pub mac: MacAddr,
}

pub struct BridgeInfo {
    pub name: String,
    pub index: u32,
    pub address: MacAddr,
}

pub fn get_local_al_mac(interface_name: String) -> Option<MacAddr> {
    // Fetch all network interfaces
    let interfaces = datalink::interfaces();

    // Find the first Ethernet interface (`ethX`)
    if let Some(iface) = interfaces.iter().find(|iface| iface.name.starts_with(&interface_name)) {
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
        .and_then(|iface| iface.mac) // Extract and return MAC address if found
        {
            tracing::debug!("Ethernet interface found for forwarding {mac_addr}");
            Some(mac_addr)
        }
        else{
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

/// Retrieves a list of all physical ethernet interfaces.
pub fn get_physical_ethernet_interfaces() -> Vec<InterfaceInfo> {
    let interfaces = netdev::get_interfaces();
    interfaces.into_iter()
        .filter_map(|interface| {
            if interface.if_type != InterfaceType::Ethernet || !interface.is_physical() {
                return None;
            }
            Some(InterfaceInfo {
                name: interface.name,
                mac: interface.mac_addr?.octets().into(),
            })
        })
        .collect()
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

pub fn get_bridge_of(interface_name: &str) -> Option<BridgeInfo> {
    let path = format!("/sys/class/net/{interface_name}/brport/bridge");
    let link = fs::read_link(&path).ok()?;

    Some(BridgeInfo {
        name: link.file_name()?.to_string_lossy().into_owned(),
        index: fs::read_to_string(format!("{path}/ifindex")).ok()?.trim().parse().ok()?,
        address: fs::read_to_string(format!("{path}/address")).ok()?.trim().parse().ok()?,
    })
}

/// Retrieves VLAN ID from `/proc/net/vlan/config`
pub fn get_vlan_id(interface_name: &str) -> Option<u16> {
    let contents = fs::read_to_string("/proc/net/vlan/config").ok()?;
    for line in contents.lines().skip(2) { // Skip headers
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
        .arg(interface_name)  // Now filters by specific interface
        .output();

    if let Ok(output) = output {
        if let Ok(stdout) = str::from_utf8(&output.stdout) { // Convert raw output to string
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
        Ok(MacAddr::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]))
    } else {
        Err(())
    }
}

pub async fn get_interfaces() -> anyhow::Result<Vec<Ieee1905InterfaceData>> {
    let mut interfaces = IndexMap::new();
    for ethernet in get_all_interfaces().await? {
        let interface = Ieee1905InterfaceData {
            mac: ethernet.mac,
            media_type: MediaType::ETHERNET_802_3ab,
            bridging_flag: ethernet.bridge_if_index.is_some(),
            bridging_tuple: ethernet.bridge_if_index,
            vlan: ethernet.vlan_id,
            metric: None,
            non_ieee1905_neighbors: None,
            ieee1905_neighbors: None,
        };
        interfaces.insert(ethernet.if_index, (interface, ethernet));
    }
    for wireless in get_wireless_interfaces().await? {
        let Some((interface, ethernet)) = interfaces.get_mut(&wireless.if_index) else {
            warn!(
                if_index = wireless.if_index,
                if_name = wireless.if_name,
                mac_addr = %wireless.mac,
                "interface not found",
            );
            continue;
        };
        if wireless.mac != ethernet.mac {
            warn!(
                if_index = ethernet.if_index,
                if_name_w = wireless.if_name,
                if_name_e = ethernet.if_name,
                addr_w = %wireless.mac,
                addr_e = %ethernet.mac,
                "wireless and ethernet interfaces have different mac",
            );
            continue;
        }
        interface.media_type = wireless.media_type;
        let _ = wireless.channel_width;
        let _ = wireless.center_freq_index1;
        let _ = wireless.center_freq_index2;
    }
    Ok(interfaces.into_values().map(|e| e.0).collect())
}

#[derive(Debug)]
struct EthernetInterfaceInfo {
    mac: MacAddr,
    if_index: i32,
    if_name: String,
    bridge_if_index: Option<u32>,
    vlan_id: Option<u16>,
}

async fn get_all_interfaces() -> anyhow::Result<Vec<EthernetInterfaceInfo>> {
    let socket = NlRouter::connect(NlFamily::Route, None, Groups::empty()).await?.0;
    let if_info_msg = IfinfomsgBuilder::default()
        .ifi_family(RtAddrFamily::Unspecified)
        .build()?;

    let mut recv: NlRouterReceiverHandle<Rtm, Ifinfomsg> = socket.send(
        Rtm::Getlink,
        NlmF::DUMP | NlmF::ACK,
        NlPayload::Payload(if_info_msg),
    ).await?;

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

        if let Ok(stats) = attr_handle.get_attr_payload_as_with_len_borrowed::<&[u8]>(Ifla::Stats) {
            debug_assert_eq!(stats.len(), size_of::<RtnlLinkStats>());
            let _stats = unsafe { std::ptr::read_unaligned(stats.as_ptr().cast::<RtnlLinkStats>()) };
        }

        if let Ok(stats) = attr_handle.get_attr_payload_as_with_len_borrowed::<&[u8]>(Ifla::Stats64) {
            debug_assert_eq!(stats.len(), size_of::<RtnlLinkStats64>());
            let _stats = unsafe { std::ptr::read_unaligned(stats.as_ptr().cast::<RtnlLinkStats64>()) };
        }

        let mut vlan_id = None;
        if let Ok(attribute) = attr_handle.get_nested_attributes::<IflaInfo>(Ifla::Linkinfo) {
            let kind = attribute.get_attr_payload_as_with_len_borrowed::<&[u8]>(IflaInfo::Kind)?;
            match kind {
                b"vlan\0" => {
                    let data = attribute.get_nested_attributes::<IflaVlan>(IflaInfo::Data)?;
                    let id = data.get_attr_payload_as::<u16>(IflaVlan::Id)?;
                    vlan_id = Some(id);
                }
                b"veth\0" => {}
                b"bridge\0" => {}
                _ => {}
            }
        }

        let if_index = i32::from(*payload.ifi_index());
        let bridge_if_index = attr_handle.get_attr_payload_as::<u32>(Ifla::Master).ok();

        interfaces.push(EthernetInterfaceInfo {
            mac: MacAddr::from(mac),
            if_index,
            if_name,
            bridge_if_index,
            vlan_id,
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
    frequency: u32,
    channel_width: Option<Nl80211ChannelWidth>,
    center_freq_index1: Option<u8>,
    center_freq_index2: Option<u8>,
    media_type: MediaType,
}

async fn get_wireless_interfaces() -> anyhow::Result<Vec<WirelessInterfaceInfo>> {
    let socket = NlRouter::connect(NlFamily::Generic, None, Groups::empty()).await?.0;
    let family_id = socket.resolve_genl_family(NL80211_GENL_NAME).await?;

    let nl_message_attrs = NlattrBuilder::default()
        .nla_type(AttrTypeBuilder::default().nla_type(Nl80211Attribute::IfName).build()?)
        .nla_payload(())
        .build()?;

    let nl_message = GenlmsghdrBuilder::<Nl80211Command, Nl80211Attribute, NoUserHeader>::default()
        .cmd(Nl80211Command::GetInterface)
        .attrs(GenlBuffer::from_iter([nl_message_attrs]))
        .version(1)
        .build()?;

    let mut recv: NlRouterReceiverHandle<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>> = socket.send(
        family_id,
        NlmF::DUMP | NlmF::ACK,
        NlPayload::Payload(nl_message),
    ).await?;

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

        let channel_width = handle.get_attr_payload_as(Nl80211Attribute::ChannelWidth).ok();
        let center_freq1 = handle.get_attr_payload_as(Nl80211Attribute::CenterFreq1).ok();
        let center_freq2 = handle.get_attr_payload_as(Nl80211Attribute::CenterFreq2).ok();

        interfaces.push(WirelessInterfaceInfo {
            mac: MacAddr::from(mac),
            bssid: None,
            if_index,
            if_name,
            frequency,
            channel_width,
            center_freq_index1: center_freq1.and_then(get_wifi_center_frequency_index),
            center_freq_index2: center_freq2.and_then(get_wifi_center_frequency_index),
            media_type: MediaType::WIRELESS_802_11b_2_4,
        });
    }

    for interface in interfaces.iter_mut() {
        let nl_attrs = NlattrBuilder::default()
            .nla_type(AttrTypeBuilder::default().nla_type(Nl80211Attribute::IfIndex).build()?)
            .nla_payload(interface.if_index)
            .build()?;

        let nl_message = GenlmsghdrBuilder::default()
            .cmd(Nl80211Command::GetStation)
            .attrs(GenlBuffer::from_iter([nl_attrs]))
            .version(1)
            .build()?;

        let mut recv: NlRouterReceiverHandle<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>> = socket.send(
            family_id,
            NlmF::DUMP | NlmF::ACK,
            NlPayload::Payload(nl_message),
        ).await?;

        while let Some(message) = recv.next().await {
            let message: Nlmsghdr<GenlId, Genlmsghdr<Nl80211Command, Nl80211Attribute>> = message?;
            let Some(payload) = message.get_payload() else {
                continue;
            };

            let handle = payload.attrs().get_attr_handle();
            interface.bssid = handle.get_attr_payload_as::<[u8; 6]>(Nl80211Attribute::Mac)
                .ok()
                .map(MacAddr::from);

            if let Ok(sta_info) = handle.get_nested_attributes::<Nl80211StaInfo>(Nl80211Attribute::StaInfo) {
                if let Some(rate_info) = sta_info.get_attribute(Nl80211StaInfo::TxBitrate) {
                    let rate_info = rate_info.get_attr_handle::<Nl80211RateInfo>()?;
                    interface.media_type = get_wireless_media_type(interface.frequency, &rate_info);
                }
            }
        }
    }

    Ok(interfaces)
}

fn get_wireless_media_type(frequency: u32, rate_info: &GenlAttrHandle<Nl80211RateInfo>) -> MediaType {
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

    let bitrate = rate_info.get_attr_payload_as::<u32>(Nl80211RateInfo::Bitrate32).unwrap_or_default();
    if bitrate > 11_0 {
        // 802.11b
        MediaType::WIRELESS_802_11b_2_4
    } else {
        // 802.11g
        MediaType::WIRELESS_802_11g_2_4
    }
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
