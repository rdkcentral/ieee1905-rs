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
use tokio::time::{interval, Duration};

// Internal modules
use crate::interface_manager::{get_neighbor_macs, get_vlan_id, is_bridge_member};
use crate::topology_manager::{Ieee1905DeviceData, Ieee1905InterfaceData, TopologyDatabase};



/// Scans all interfaces and updates their list of neighbor MAC addresses.
use tracing::{info, debug, trace};
use crate::cmdu_codec::MediaType;

/// Scans all interfaces and updates their list of neighbor MAC addresses.
pub fn scan_edge_devices() -> Vec<Ieee1905InterfaceData> {
    let mut interfaces = Vec::new();

    // Get all available interfaces from netdev and pnet
    let netdev_interfaces = netdev::get_interfaces();
    let pnet_interfaces = datalink::interfaces();

    for iface in pnet_interfaces {
        if let Some(mac) = iface.mac {
            let interface_name = iface.name.clone();
            debug!("Scanning interface: {} (MAC: {})", interface_name, mac);

            // Find the corresponding netdev interface
            if let Some(_net_iface) = netdev_interfaces.iter().find(|n| n.name == interface_name) {

                // Determine the media type
                let media_type;
                let metric;
                if interface_name.starts_with("eth") {
                    media_type = MediaType::ETHERNET_802_3u; // Ethernet
                    metric = Some(10);
                } else if interface_name.starts_with("wl") || interface_name.starts_with("wlan") {
                    media_type = MediaType::WIRELESS_802_11b_2_4; // Wi-Fi
                    metric = Some(100);
                } else {
                    continue; // Skip non-Ethernet/Wi-Fi interfaces
                };

                let bridging_flag = is_bridge_member(&interface_name);
                let bridging_tuple = if bridging_flag { Some(0) } else { None };
                let vlan = get_vlan_id(&interface_name);

                // Scan for neighbors on this interface
                let non_ieee1905_neighbors: Option<Vec<MacAddr>> = Some(get_neighbor_macs(&interface_name));

                // Log found neighbors
                if let Some(ref neighbors) = non_ieee1905_neighbors {
                    if !neighbors.is_empty() {
                        info!(
                            "Found {} neighbor(s) on interface {}: {:?}",
                            neighbors.len(),
                            interface_name,
                            neighbors
                        );
                    } else {
                        trace!("No neighbors found on interface {}", interface_name);
                    }
                }

                // Create an IEEE1905Interface object
                let ieee_interface = Ieee1905InterfaceData::new(
                    mac,
                    media_type,
                    bridging_flag,
                    bridging_tuple,
                    vlan,
                    metric,
                    non_ieee1905_neighbors,
                    None,
                );

                interfaces.push(ieee_interface);
            }
        }
    }

    info!("Scanning complete. Total interfaces processed: {}", interfaces.len());
    interfaces
}



/// Periodically updates all IEEE1905 devices with the latest neighbor MAC addresses.
pub async fn update_edge_devices(al_mac: MacAddr, interface_name: String) {
    // Get the singleton instance of the topology database
    let topology_db = TopologyDatabase::get_instance(al_mac, interface_name).await;

    // Create a ticker that triggers every 5 seconds
    let mut ticker = interval(Duration::from_secs(5));

    loop {
        // Wait for the next tick (does not block)
        ticker.tick().await;

        // Get scanned interfaces with updated neighbor MACs
        let updated_interfaces = scan_edge_devices();

        // Retrieve the existing node from the topology
        if let Some(node) = topology_db.get_device(al_mac).await {
            tracing::info!(
                "Updating device {}: {} interfaces found",
                al_mac,
                updated_interfaces.len()
            );

            // Create updated device data
            let _updated_device_data = Ieee1905DeviceData {
                al_mac,
                destination_frame_mac: al_mac,
                destination_mac: node.device_data.destination_mac,
                local_interface_list: Some(updated_interfaces),
                registry_role: None,
            };

            // Save updated device in the topology
            // topology_db.update_ieee1905_topology(updated_device_data, UpdateType::LocalScan, None).await;

            tracing::info!("Updated device {} with new interface list and neighbors", al_mac);
        } else {
            tracing::warn!("Device {} not found in topology", al_mac);
        }
    }
}


