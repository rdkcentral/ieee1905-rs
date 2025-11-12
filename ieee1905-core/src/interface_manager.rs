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
// External crates
use pnet::datalink::{self, MacAddr};

// Standard library
use std::collections::{HashMap, HashSet};
use std::fs;
use std::process::Command;
use std::str;
use netdev::interface::InterfaceType;
// Internal modules
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
pub fn get_vlan_id(interface_name: &str) -> Option<u8> {
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


/// Retrieves a list of interfaces with additional metadata.
pub fn get_interfaces() -> Vec<Ieee1905InterfaceData> {
    let mut interfaces = Vec::new();
    let mut interfaces_by_bridge = HashMap::<u32, Vec<MacAddr>>::new();

    let netdev_interfaces = netdev::get_interfaces();
    let pnet_interfaces = datalink::interfaces();

    for iface in pnet_interfaces {
        if let Some(mac) = iface.mac {
            let interface_name = iface.name.clone();

            // Find corresponding netdev interface
            if let Some(net_iface) = netdev_interfaces.iter().find(|n| n.name == interface_name) {

                // Determine media type
                let media_type = match net_iface.if_type {
                    InterfaceType::Ethernet => 0x01,        // Ethernet
                    InterfaceType::Wireless80211 => 0x0100, // Wi-Fi
                    _ => continue,                          // Skip non-Ethernet/Wi-Fi interfaces
                };

                let metric = if media_type == 0x01 { Some(10) } else { Some(100) };

                let vlan = get_vlan_id(&net_iface.name);
                //let non_ieee1905_neighbors = Some(get_neighbor_macs(&interface_name));
                let non_ieee1905_neighbors = None;
                let ieee1905_neighbors = None;

                if let Some(bridging_info) = get_bridge_of(&interface_name) {
                    interfaces_by_bridge.entry(bridging_info.index).or_default().push(mac);
                }

                interfaces.push(Ieee1905InterfaceData {
                    mac,
                    media_type,
                    bridging_flag: false,
                    bridging_tuple: None,
                    vlan,
                    metric,
                    non_ieee1905_neighbors,
                    ieee1905_neighbors,
                });
            }
        }
    }

    let mut bridge_index_by_interface = HashMap::<MacAddr, u8>::new();
    for (index, bridged_interfaces) in interfaces_by_bridge.into_values().enumerate() {
        for interface in bridged_interfaces {
            bridge_index_by_interface.insert(interface, index as u8);
        }
    }

    for interface in interfaces.iter_mut() {
        if let Some(index) = bridge_index_by_interface.get(&interface.mac) {
            interface.bridging_flag = true;
            interface.bridging_tuple = Some(*index);
        }
    }

    interfaces
}
