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
#![allow(clippy::too_many_arguments)]
// External crates
use crossterm::{
    event::{self, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pnet::datalink::MacAddr;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Terminal,
};
use tokio::{
    sync::RwLock,
    task::yield_now,
    time::{interval, Duration, Instant},
};
use tracing::{debug, error, info, instrument};
// Standard library
use indexmap::IndexMap;
use neli::consts::rtnl::Iff;
use std::ops::Deref;
use std::sync::OnceLock;
use std::{io, sync::Arc};
use tokio::sync::{RwLockMappedWriteGuard, RwLockWriteGuard};
use tokio::task::JoinSet;
// Internal modules
use crate::cmdu_codec::{
    CMDUFragmentation, DeviceIdentificationType, Ieee1905ProfileVersion, LinkMetricQuery,
    MediaType, MediaTypeSpecialInfo, Profile2ApCapability, SupportedFreqBand,
};
use crate::interface_manager::get_interfaces;
use crate::linux::if_link::RtnlLinkStats64;
use crate::lldpdu::PortId;
use crate::{
    cmdu::IEEE1905Neighbor, interface_manager::get_forwarding_interface_mac, next_task_id,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateLocal {
    Idle,
    ConvergingLocal(Instant),
    ConvergedLocal,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateRemote {
    Idle,
    ConvergingRemote(Instant),
    ConvergedRemote,
}

/// Synchronization state of a node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateType {
    LldpUpdate,
    DiscoveryReceived,
    NotificationReceived,
    QuerySent,
    QueryReceived,
    ResponseSent,
    ResponseReceived,
    ApAutoConfigSearch,
}

pub enum TransmissionEvent {
    SendTopologyQuery(MacAddr),
    SendTopologyResponse(MacAddr),
    SendTopologyNotification(MacAddr),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ieee1905LocalInterface {
    pub name: String,
    pub index: i32,
    pub flags: Iff,
    pub link_stats: Option<RtnlLinkStats64>,
    pub data: Ieee1905InterfaceData,
}

impl Deref for Ieee1905LocalInterface {
    type Target = Ieee1905InterfaceData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ieee1905InterfaceData {
    pub mac: MacAddr,
    pub media_type: MediaType,
    pub media_type_extra: MediaTypeSpecialInfo,
    pub bridging_flag: bool,
    pub bridging_tuple: Option<u32>,
    pub vlan: Option<u16>,
    pub metric: Option<u16>,
    pub phy_rate: Option<u64>,
    pub link_availability: Option<u8>,
    pub signal_strength_dbm: Option<i8>,
    pub non_ieee1905_neighbors: Option<Vec<MacAddr>>,
    pub ieee1905_neighbors: Option<Vec<IEEE1905Neighbor>>,
}

impl Ieee1905InterfaceData {
    pub fn new(
        mac: MacAddr,
        media_type: MediaType,
        bridging_flag: bool,
        bridging_tuple: Option<u32>,
        vlan: Option<u16>,
        metric: Option<u16>,
        non_ieee1905_neighbors: Option<Vec<MacAddr>>,
        ieee1905_neighbors: Option<Vec<IEEE1905Neighbor>>,
    ) -> Self {
        Self {
            mac,
            media_type,
            media_type_extra: Default::default(),
            bridging_flag,
            bridging_tuple,
            vlan,
            metric,
            phy_rate: None,
            link_availability: None,
            signal_strength_dbm: None,
            non_ieee1905_neighbors,
            ieee1905_neighbors,
        }
    }

    pub fn update(
        &mut self,
        new_bridging_flag: Option<bool>,
        new_bridging_tuple: Option<u32>,
        new_vlan: Option<u16>,
        new_metric: Option<u16>,
        new_non_ieee1905_neighbors: Option<Vec<MacAddr>>,
        new_ieee1905_neighbors: Option<Vec<IEEE1905Neighbor>>,
    ) {
        if let Some(bridging_flag) = new_bridging_flag {
            self.bridging_flag = bridging_flag;
        }
        if let Some(bridging_tuple) = new_bridging_tuple {
            self.bridging_tuple = Some(bridging_tuple);
        }
        if let Some(vlan) = new_vlan {
            self.vlan = Some(vlan);
        }
        if let Some(metric) = new_metric {
            self.metric = Some(metric);
        }
        if let Some(non_ieee_neighbors) = new_non_ieee1905_neighbors {
            self.non_ieee1905_neighbors = Some(non_ieee_neighbors);
        }
        if let Some(ieee1905_neighbors) = new_ieee1905_neighbors {
            self.ieee1905_neighbors = Some(ieee1905_neighbors);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ieee1905NodeInfo {
    pub al_mac: MacAddr,
    pub last_update: UpdateType,
    pub last_seen: Instant,
    /// last msg id sent to this node
    /// this excludes response ids, those are always copied from the query
    pub local_message_id: Option<u16>,
    /// last msg id received from this node
    /// this excludes response ids, those are always copied from the query
    pub remote_message_id: Option<u16>,
    pub lldp_neighbor: Option<PortId>,
    pub node_state_local: StateLocal,
    pub node_state_remote: StateRemote,
}

impl Ieee1905NodeInfo {
    /// **Create a new `Ieee1905NodeInfo` instance**
    pub fn new(
        al_mac: MacAddr,
        last_update: UpdateType,
        lldp_neighbor: Option<PortId>,
        node_state_local: StateLocal,
        node_state_remote: StateRemote,
    ) -> Self {
        Self {
            al_mac,
            last_update,
            last_seen: Instant::now(), // Set current time at creation
            local_message_id: None,
            remote_message_id: None,
            lldp_neighbor,
            node_state_local,
            node_state_remote,
        }
    }

    /// **Update existing `Ieee1905NodeInfo` fields**
    pub fn update(
        &mut self,
        new_state: Option<UpdateType>,
        new_local_message_id: Option<u16>,
        new_remote_message_id: Option<u16>,
        new_lldp_neighbor: Option<PortId>,
        new_node_state_local: Option<StateLocal>,
        new_node_state_remote: Option<StateRemote>,
    ) {
        if let Some(message_type) = new_state {
            self.last_update = message_type;
        }
        if let Some(message_id) = new_local_message_id {
            self.local_message_id = Some(message_id);
        }
        if let Some(message_id) = new_remote_message_id {
            self.remote_message_id = Some(message_id);
        }
        if let Some(lldp_neighbor) = new_lldp_neighbor {
            self.lldp_neighbor = Some(lldp_neighbor);
        }

        if let Some(local) = new_node_state_local {
            if self.node_state_local != local {
                info!(
                    "{} local state changed: {:?} -> {local:?}",
                    self.al_mac, self.node_state_local
                );
                self.node_state_local = local;
            }
        }

        if let Some(remote) = new_node_state_remote {
            if self.node_state_remote != remote {
                info!(
                    "{} remote state changed: {:?} -> {remote:?}",
                    self.al_mac, self.node_state_remote
                );
                self.node_state_remote = remote;
            }
        }

        self.last_seen = Instant::now();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Registrar,
    Enrollee,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ieee1905DeviceData {
    pub al_mac: MacAddr,
    pub destination_frame_mac: MacAddr,
    pub destination_mac: Option<MacAddr>,
    pub local_interface_mac: MacAddr,
    pub local_interface_list: Option<Vec<Ieee1905InterfaceData>>,
    pub registry_role: Option<Role>,
    pub supported_fragmentation: CMDUFragmentation,
    pub supported_freq_band: Option<SupportedFreqBand>,
    pub ieee1905profile_version: Option<Ieee1905ProfileVersion>,
    pub device_identification_type: Option<DeviceIdentificationType>,
}

impl Ieee1905DeviceData {
    /// **Create a new `Ieee1905DeviceData`**
    pub fn new(
        al_mac: MacAddr,
        destination_frame_mac: MacAddr,
        destination_mac: Option<MacAddr>,
        local_interface_mac: MacAddr,
        local_interface_list: Option<Vec<Ieee1905InterfaceData>>,
        registry_role: Option<Role>,
    ) -> Self {
        Self {
            al_mac,
            destination_frame_mac,
            destination_mac,
            local_interface_mac,
            local_interface_list,
            registry_role,
            supported_fragmentation: Default::default(),
            supported_freq_band: None,
            ieee1905profile_version: None,
            device_identification_type: None,
        }
    }

    /// **Update existing `Ieee1905DeviceData` fields**
    pub fn update_from(&mut self, other: Self) -> bool {
        let mut changed = false;
        if let Some(destination_mac) = other.destination_mac {
            changed = true;
            self.destination_mac = Some(destination_mac);
        }
        if let Some(interfaces) = other.local_interface_list {
            changed = true;
            self.local_interface_list = Some(interfaces);
        }
        if let Some(value) = other.ieee1905profile_version {
            changed = true;
            self.ieee1905profile_version = Some(value);
        }
        if let Some(value) = other.device_identification_type {
            changed = true;
            self.device_identification_type = Some(value);
        }
        changed
    }

    pub fn has_changed(&self, other: &Self) -> bool {
        self.local_interface_list != other.local_interface_list
    }

    pub fn has_port(&self, mac: MacAddr) -> bool {
        if self.al_mac == mac {
            return true;
        }
        if self.destination_frame_mac == mac {
            return true;
        }
        if self.destination_mac == Some(mac) {
            return true;
        }
        self.local_interface_list
            .as_ref()
            .is_some_and(|e| e.iter().any(|e| e.mac == mac))
    }
}

#[derive(Clone, Debug)]
pub struct Ieee1905Node {
    pub metadata: Ieee1905NodeInfo, // Metadata containing state, timestamps, message_id, etc.
    pub device_data: Ieee1905DeviceData, // Device-related information
}

impl Ieee1905Node {
    /// **Create a new `Ieee1905Node` instance**
    pub fn new(metadata: Ieee1905NodeInfo, device_data: Ieee1905DeviceData) -> Self {
        Self {
            metadata,
            device_data,
        }
    }

    /// **Update existing `Ieee1905Node` fields**
    pub fn update(
        &mut self,
        new_metadata: Option<Ieee1905NodeInfo>,
        new_device_data: Option<Ieee1905DeviceData>,
    ) {
        if let Some(metadata) = new_metadata {
            self.metadata = metadata;
        }
        if let Some(device_data) = new_device_data {
            self.device_data = device_data;
        }
    }
}

static TOPOLOGY_DATABASE: OnceLock<Arc<TopologyDatabase>> = OnceLock::new();

#[derive(Debug)]
pub struct TopologyDatabase {
    pub al_mac_address: MacAddr,
    pub interface_name: String,
    pub local_mac: Arc<RwLock<MacAddr>>,
    pub local_interface_list: Arc<RwLock<Option<Vec<Ieee1905LocalInterface>>>>,
    pub nodes: Arc<RwLock<IndexMap<MacAddr, Ieee1905Node>>>,
    pub local_role: Arc<RwLock<Option<Role>>>,
}

impl TopologyDatabase {
    /// **Creates a new `TopologyDatabase` instance**
    fn new(al_mac_address: MacAddr, interface_name: String) -> Arc<Self> {
        debug!(al_mac = %al_mac_address, "Database initialized");

        // TODO this db should be initialized eagerly from main, and propagated as a dependency

        // Get local MAC address from forwarding interface
        let local_mac = get_forwarding_interface_mac(&interface_name);

        Arc::new(Self {
            al_mac_address,
            interface_name,
            local_mac: Arc::new(RwLock::new(local_mac)),
            local_interface_list: Arc::new(RwLock::new(None)),
            nodes: Arc::new(RwLock::new(IndexMap::new())),
            local_role: Arc::new(RwLock::new(None)),
        })
    }

    pub fn start_workers(self: &Arc<Self>) -> JoinSet<()> {
        let mut set = JoinSet::new();
        set.spawn(self.clone().refresh_topology_worker());
        set.spawn(self.clone().refresh_interfaces_worker());
        set
    }

    /// ** Returns the local role
    pub async fn get_local_role(&self) -> Option<Role> {
        *self.local_role.read().await
    }
    /// ** Sets the local role
    pub async fn set_local_role(&self, role: Option<Role>) {
        let mut write_guard = self.local_role.write().await;
        *write_guard = role;
    }

    pub async fn get_forwarding_interface_mac(&self) -> MacAddr {
        let mac_guard = self.local_mac.read().await;
        *mac_guard
    }

    /// **Returns a globally shared `TopologyDatabase` instance (async)**
    pub fn get_instance(al_mac_address: MacAddr, interface_name: &str) -> Arc<TopologyDatabase> {
        TOPOLOGY_DATABASE
            .get_or_init(|| TopologyDatabase::new(al_mac_address, interface_name.to_owned()))
            .clone()
    }

    /// **Returns a globally shared `TopologyDatabase` instance if constructed (sync)**
    pub fn peek_instance_sync() -> Option<&'static Arc<TopologyDatabase>> {
        TOPOLOGY_DATABASE.get()
    }

    /// **Retrieves a device node from the database**
    pub async fn get_device(&self, al_mac: MacAddr) -> Option<Ieee1905Node> {
        let nodes = self.nodes.read().await; // Read lock
        nodes.get(&al_mac).cloned() // Clone to return the device node
    }

    /// **Retrieves a device node from the database**
    pub async fn find_device_by_port(&self, mac: MacAddr) -> Option<Ieee1905Node> {
        let nodes = self.nodes.read().await;
        Self::find_node_by_port(nodes.values(), mac).cloned()
    }

    pub async fn lock_node_by_port_mut(
        &self,
        mac: MacAddr,
    ) -> Option<RwLockMappedWriteGuard<'_, Ieee1905Node>> {
        let nodes = self.nodes.write().await;
        RwLockWriteGuard::try_map(nodes, |e| Self::find_node_by_port_mut(e.values_mut(), mac)).ok()
    }

    fn find_node_by_port<'a, I>(mut iter: I, mac: MacAddr) -> Option<&'a Ieee1905Node>
    where
        I: Iterator<Item = &'a Ieee1905Node>,
    {
        iter.find(|node| node.device_data.has_port(mac))
    }

    fn find_node_by_port_mut<'a, I>(mut iter: I, mac: MacAddr) -> Option<&'a mut Ieee1905Node>
    where
        I: Iterator<Item = &'a mut Ieee1905Node>,
    {
        iter.find(|node| node.device_data.has_port(mac))
    }

    /// **Getter for `local_interface_list`**
    pub async fn get_local_interface_list(&self) -> Option<Vec<Ieee1905LocalInterface>> {
        let local_interfaces = self.local_interface_list.read().await;
        local_interfaces.clone() // Clone the data to avoid holding the lock
    }

    pub async fn get_last_update(&self, al_mac: MacAddr) -> Option<UpdateType> {
        let nodes = self.nodes.read().await;
        nodes.get(&al_mac).map(|node| node.metadata.last_update)
    }

    pub async fn get_last_seen(&self, al_mac: MacAddr) -> Option<Instant> {
        let nodes = self.nodes.read().await;
        nodes.get(&al_mac).map(|node| node.metadata.last_seen)
    }

    pub async fn get_node_states(&self, al_mac: MacAddr) -> Option<(StateLocal, StateRemote)> {
        let nodes = self.nodes.read().await;
        let node = nodes.get(&al_mac)?;
        Some((
            node.metadata.node_state_local,
            node.metadata.node_state_remote,
        ))
    }

    fn update_local_neighbours_ieee1905_compatibility(
        interfaces: &mut [Ieee1905LocalInterface],
        ieee1905_nodes: &IndexMap<MacAddr, Ieee1905Node>,
    ) {
        for interface in interfaces {
            let Some(neighbors) = interface.data.non_ieee1905_neighbors.as_mut() else {
                continue;
            };

            let ieee1905_neighbors = interface.data.ieee1905_neighbors.get_or_insert_default();
            ieee1905_neighbors.extend(
                neighbors
                    .extract_if(.., |e| {
                        Self::find_node_by_port(ieee1905_nodes.values(), *e).is_some()
                    })
                    .map(|e| IEEE1905Neighbor {
                        neighbor_al_mac: e,
                        neighbor_flags: 0,
                    }),
            );
        }
    }

    #[instrument(skip_all, name = "topo_db_refresh_topology", fields(task = next_task_id()))]
    async fn refresh_topology_worker(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_secs(5)); // Runs every 5 seconds

        loop {
            ticker.tick().await; // Wait for the next tick
            let mut nodes = self.nodes.write().await;
            let now = Instant::now();

            nodes.retain(|al_mac, node| {
                // Remove nodes stuck in ConvergingLocal state
                if let StateLocal::ConvergingLocal(when) = node.metadata.node_state_local {
                    if now.duration_since(when) >= Duration::from_secs(5) {
                        debug!(
                            al_mac = ?al_mac,
                            state = ?node.metadata.last_update,
                            "Removing node stuck in local convergence for too long"
                        );
                        return false; // Remove from database
                    }
                }

                // Remove nodes stuck in ConvergingRemote state
                if let StateRemote::ConvergingRemote(when) = node.metadata.node_state_remote {
                    if now.duration_since(when) >= Duration::from_secs(5) {
                        debug!(
                            al_mac = ?al_mac,
                            state = ?node.metadata.last_update,
                            "Removing node stuck in remote convergence for too long"
                        );
                        return false; // Remove from database
                    }
                }

                // Remove nodes that have been inactive
                let elapsed = now.duration_since(node.metadata.last_seen);
                if elapsed >= Duration::from_secs(60) {
                    tracing::debug!(al_mac = ?al_mac, "Removing node due to timeout");
                    return false; // Remove from database
                }

                debug!(
                    al_mac = ?al_mac,
                    elapsed_time = elapsed.as_secs_f64(),
                    "Node Last Seen"
                );
                true // Keep the node
            });

            if nodes.is_empty() {
                debug!("No nodes in the topology, waiting for updates...");
            }
        }
    }

    #[instrument(skip_all, name = "topo_db_refresh_interfaces", fields(task = next_task_id()))]
    async fn refresh_interfaces_worker(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(100));

        loop {
            interval.tick().await;

            match get_interfaces().await {
                Ok(interfaces) => {
                    let mut list = self.local_interface_list.write().await;

                    if let Some(list) = list.as_mut() {
                        let nodes = self.nodes.read().await;
                        Self::update_local_neighbours_ieee1905_compatibility(list, &nodes);
                    }

                    if interfaces.is_empty() {
                        *list = None;
                        debug!("No interfaces found — set to None");
                    } else {
                        *list = Some(interfaces);
                        debug!("Updated local interfaces");
                    }
                }
                Err(e) => {
                    error!("Interface scan task panicked: {:?}", e);
                }
            }

            *self.local_mac.write().await = get_forwarding_interface_mac(&self.interface_name);
        }
    }

    /// Tie breaker function in case we need to give priority in case of collision
    pub async fn tiebreaker(&self, remote_al_mac: MacAddr) -> bool {
        let local_mac = self.al_mac_address;
        let local_last = local_mac.5;
        let remote_last = remote_al_mac.5;

        local_last < remote_last
    }
    /// **Adds or updates a node in the topology database**
    pub async fn update_ieee1905_topology(
        &self,
        device_data: Ieee1905DeviceData,
        operation: UpdateType,
        local_msg_id: Option<u16>,
        remote_msg_id: Option<u16>,
        lldp_neighbor: Option<PortId>,
    ) -> TransmissionEvent {
        let al_mac = device_data.al_mac;
        let transmission_event;

        //TODO: use new update types.
        tracing::debug!("WAITING for write lock");
        {
            let mut nodes = self.nodes.write().await;
            tracing::debug!("ACQUIRED write lock");

            match nodes.get_mut(&al_mac) {
                Some(node) => {
                    tracing::debug!(al_mac = ?al_mac, operation = ?operation, "Updating existing node");

                    node.device_data.local_interface_mac = device_data.local_interface_mac;

                    transmission_event = match operation {
                        UpdateType::DiscoveryReceived => {
                            let local_state = node.metadata.node_state_local;

                            node.device_data.update_from(device_data);
                            node.metadata.update(
                                Some(operation),
                                local_msg_id,
                                remote_msg_id,
                                None,
                                None,
                                None,
                            );

                            if local_state == StateLocal::Idle {
                                TransmissionEvent::SendTopologyQuery(al_mac)
                            } else {
                                TransmissionEvent::None
                            }
                        }
                        UpdateType::NotificationReceived => {
                            let local_state = node.metadata.node_state_local;

                            if local_state == StateLocal::ConvergedLocal {
                                node.metadata.update(
                                    Some(operation),
                                    local_msg_id,
                                    remote_msg_id,
                                    None,
                                    Some(StateLocal::Idle),
                                    None,
                                );
                                TransmissionEvent::SendTopologyQuery(al_mac)
                            } else {
                                TransmissionEvent::None
                            }
                        }
                        UpdateType::QueryReceived => {
                            let remote_state = node.metadata.node_state_remote;

                            if remote_state != StateRemote::ConvergedRemote {
                                node.metadata.update(
                                    Some(operation),
                                    local_msg_id,
                                    remote_msg_id,
                                    None,
                                    None,
                                    Some(StateRemote::ConvergingRemote(Instant::now())),
                                );
                                debug!("Event: Send Topology Response");
                                TransmissionEvent::SendTopologyResponse(al_mac)
                            } else {
                                TransmissionEvent::None
                            }
                        }

                        UpdateType::ResponseReceived => {
                            let local_state = node.metadata.node_state_local;

                            if let StateLocal::ConvergingLocal(_) = local_state {
                                node.metadata.update(
                                    Some(operation),
                                    local_msg_id,
                                    remote_msg_id,
                                    None,
                                    Some(StateLocal::ConvergedLocal),
                                    None,
                                );

                                debug!(
                                    current_local_interface_list = ?node.device_data.local_interface_list,
                                    new_local_interface_list = ?device_data.local_interface_list,
                                    "Comparing local_interface_list"
                                );

                                if node.device_data.has_changed(&device_data) {
                                    debug!("Device data changed local_interface_list)");

                                    node.device_data.update_from(device_data);

                                    let multicast_mac =
                                        MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x13);
                                    debug!("Event: Send Topology Notification");
                                    TransmissionEvent::SendTopologyNotification(multicast_mac)
                                } else {
                                    debug!("Device data unchanged — no transmission needed");
                                    TransmissionEvent::None
                                }
                            } else {
                                tracing::debug!(
                                    "Ignoring ResponseReceived — Node not in ConvergingLocal state"
                                );
                                TransmissionEvent::None
                            }
                        }

                        UpdateType::QuerySent => {
                            if node.metadata.node_state_local != StateLocal::ConvergedLocal {
                                node.metadata.update(
                                    Some(operation),
                                    local_msg_id,
                                    remote_msg_id,
                                    None,
                                    Some(StateLocal::ConvergingLocal(Instant::now())),
                                    None,
                                );
                            }
                            TransmissionEvent::None
                        }
                        UpdateType::ResponseSent => {
                            if let StateRemote::ConvergingRemote(_) =
                                node.metadata.node_state_remote
                            {
                                node.metadata.update(
                                    Some(operation),
                                    local_msg_id,
                                    remote_msg_id,
                                    None,
                                    None,
                                    Some(StateRemote::ConvergedRemote),
                                );
                            }
                            TransmissionEvent::None
                        }
                        UpdateType::LldpUpdate => {
                            node.metadata.update(
                                Some(operation),
                                local_msg_id,
                                remote_msg_id,
                                lldp_neighbor.clone(),
                                None,
                                None,
                            );
                            debug!(al_mac = ?al_mac, lldp_neighbor = ?lldp_neighbor, "Updated LLDP neighbor status");
                            TransmissionEvent::None
                            //If needed we can indicate here a notification event to update topology data base in al neighbors but for now it is not needed
                            //initial DB snapshot covers current uses cases for RDK-B but we can update this part if needed in the future
                        }
                        UpdateType::ApAutoConfigSearch => TransmissionEvent::None,
                    };
                }
                None => {
                    tracing::debug!(al_mac = ?al_mac, operation = ?operation, "Node not found — inserting");

                    let mut new_node = Ieee1905Node {
                        metadata: Ieee1905NodeInfo {
                            al_mac: device_data.al_mac,
                            last_update: operation,
                            last_seen: Instant::now(),
                            local_message_id: local_msg_id,
                            remote_message_id: remote_msg_id,
                            lldp_neighbor,
                            node_state_local: StateLocal::Idle,
                            node_state_remote: StateRemote::Idle,
                        },
                        device_data,
                    };

                    let node_was_crated;
                    transmission_event = match operation {
                        UpdateType::DiscoveryReceived => {
                            nodes.insert(al_mac, new_node);
                            node_was_crated = true;
                            tracing::debug!(al_mac = ?al_mac, "Inserted node from Discovery");
                            TransmissionEvent::SendTopologyQuery(al_mac)
                        }
                        UpdateType::QueryReceived => {
                            new_node.metadata.node_state_remote =
                                StateRemote::ConvergingRemote(Instant::now());
                            nodes.insert(al_mac, new_node);
                            node_was_crated = true;
                            tracing::debug!(al_mac = ?al_mac, "Inserted node from query");
                            TransmissionEvent::SendTopologyResponse(al_mac)
                        }
                        UpdateType::ApAutoConfigSearch => {
                            nodes.insert(al_mac, new_node);
                            node_was_crated = true;
                            debug!(al_mac = ?al_mac, "Inserted node from Discovery");
                            TransmissionEvent::None
                        }
                        _ => {
                            tracing::debug!(al_mac = ?al_mac, operation = ?operation, "Insertion skipped — unsupported operation");
                            node_was_crated = false;
                            TransmissionEvent::None
                        }
                    };

                    if node_was_crated {
                        let mut interfaces = self.local_interface_list.write().await;
                        if let Some(vec) = interfaces.as_mut() {
                            Self::update_local_neighbours_ieee1905_compatibility(vec, &nodes);
                        }
                    }
                }
            };
        }

        debug!("Lock released — function continues safely");
        transmission_event
    }

    pub async fn handle_notification_sent(&self) {
        let mut nodes = self.nodes.write().await;
        for node in nodes.values_mut() {
            if let StateRemote::ConvergedRemote = node.metadata.node_state_remote {
                node.metadata
                    .update(None, None, None, None, None, Some(StateRemote::Idle));
            }
        }
    }

    pub async fn handle_link_metric_query(
        &self,
        source: MacAddr,
        query: &LinkMetricQuery,
    ) -> Option<(MacAddr, Vec<Ieee1905Node>)> {
        let nodes = self.nodes.write().await;
        let Some(node) = Self::find_node_by_port(nodes.values(), source) else {
            debug!(%source, "link_metric_query — node not found");
            return None;
        };

        let node_al_mac = node.device_data.al_mac;
        let neighbors = match query.neighbor_mac {
            Some(e) => {
                let Some(neighbor) = Self::find_node_by_port(nodes.values(), e) else {
                    debug!(%source, "link_metric_query — neighbor {e} not found");
                    return None;
                };
                vec![neighbor.clone()]
            }
            None => nodes
                .iter()
                .filter(|e| *e.0 != node_al_mac)
                .map(|e| e.1.clone())
                .collect(),
        };

        Some((node_al_mac, neighbors))
    }

    pub async fn handle_ap_auto_config_response(
        &self,
        source: MacAddr,
        supported_freq_band: SupportedFreqBand,
    ) {
        let mut nodes = self.nodes.write().await;
        let Some(node) = Self::find_node_by_port_mut(nodes.values_mut(), source) else {
            return debug!(%source, "handle_ap_auto_config_response — node not found");
        };

        node.device_data.supported_freq_band = Some(supported_freq_band);
    }

    pub async fn handle_ap_auto_config_wcs(
        &self,
        source: MacAddr,
        capability: &Profile2ApCapability,
    ) {
        let mut nodes = self.nodes.write().await;
        let Some(node) = Self::find_node_by_port_mut(nodes.values_mut(), source) else {
            return debug!(%source, "ap_auto_config_wcs — node not found");
        };

        let fragmentation = match capability.dpp_onboarding {
            true => CMDUFragmentation::ByteBoundary,
            false => CMDUFragmentation::TLVBoundary,
        };

        if node.device_data.supported_fragmentation != fragmentation {
            node.device_data.supported_fragmentation = fragmentation;
            info!(
                "node {} fragmentation changed to {fragmentation:?}",
                node.device_data.al_mac
            );
        }
    }

    pub async fn start_topology_cli(self: Arc<Self>) -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        loop {
            let local_mac = self.al_mac_address.to_string();
            let interfaces = self.local_interface_list.read().await.clone();
            let nodes = self.nodes.read().await.clone();

            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(1)
                    .constraints([
                        Constraint::Length(7),
                        Constraint::Min(10),
                        Constraint::Length(3),
                    ])
                    .split(f.area());

                // ─────────────────────── BLOQUE 1: TOPOLOGY MANAGER
                let block1 = Block::default()
                    .title("TOPOLOGY MANAGER")
                    .borders(Borders::ALL);

                let mut lines = vec![
                    Line::from(vec![Span::raw(format!("Local AL MAC: {local_mac}"))]),
                    Line::from(vec![Span::raw("Interfaces:")]),
                ];

                if let Some(interface_list) = &interfaces {
                    for iface in interface_list {
                        lines.push(Line::from(vec![Span::raw(format!(
                            "- MAC: {}, MediaType: {}",
                            iface.mac, iface.media_type,
                        ))]));
                    }
                } else {
                    lines.push(Line::from(vec![Span::raw("- No interfaces available")]));
                }

                let paragraph1 = Paragraph::new(lines)
                    .block(block1)
                    .wrap(ratatui::widgets::Wrap { trim: true });

                f.render_widget(paragraph1, chunks[0]);

                //IEEE 1905 Devices
                let block2 = Block::default()
                    .title("IEEE 1905 Devices")
                    .borders(Borders::ALL);

                let rows = nodes.iter().map(|(mac, node)| {
                    let destination_mac = node
                        .device_data
                        .destination_mac
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| "-".to_string());

                    let lldp = node
                        .metadata
                        .lldp_neighbor
                        .as_ref()
                        .map(|l| l.port_id.to_string())
                        .unwrap_or_else(|| "-".to_string());

                    let interface_mac = node
                        .device_data
                        .local_interface_list
                        .as_ref()
                        .and_then(|list| list.first())
                        .map(|iface| iface.mac.to_string())
                        .unwrap_or_else(|| "-".to_string());

                    let media_type = node
                        .device_data
                        .local_interface_list
                        .as_ref()
                        .and_then(|list| list.first())
                        .map(|iface| iface.media_type.to_string())
                        .unwrap_or_else(|| "-".to_string());

                    let last_seen_secs = node.metadata.last_seen.elapsed().as_secs();

                    Row::new(vec![
                        mac.to_string(),
                        format!("{:?}", node.metadata.node_state_local),
                        format!("{:?}", node.metadata.node_state_remote),
                        format!("{}s ago", last_seen_secs),
                        destination_mac,
                        lldp,
                        interface_mac,
                        media_type,
                    ])
                });

                let table = Table::new(
                    rows,
                    &[
                        Constraint::Length(20),
                        Constraint::Length(25),
                        Constraint::Length(25),
                        Constraint::Length(15),
                        Constraint::Length(20),
                        Constraint::Length(20),
                        Constraint::Length(20),
                        Constraint::Length(25),
                    ],
                )
                .header(Row::new(vec![
                    "AL MAC",
                    "StateLocal",
                    "StateRemote",
                    "Last Seen",
                    "DestinationMac",
                    "LLDP",
                    "Interface",
                    "Media Type",
                ]))
                .block(block2)
                .column_spacing(1);

                f.render_widget(table, chunks[1]);

                //Footer
                let block3 = Block::default().borders(Borders::ALL);
                let paragraph3 =
                    Paragraph::new(vec![Line::from(vec![Span::raw("Press 'q' to quit.")])])
                        .block(block3)
                        .wrap(ratatui::widgets::Wrap { trim: true });

                f.render_widget(paragraph3, chunks[2]);
            })?;
            yield_now().await;
            if event::poll(Duration::from_millis(500))? {
                if let event::Event::Key(key) = event::read()? {
                    if key.code == KeyCode::Char('q') {
                        break;
                    }
                }
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::cmdu_codec::MediaType;
    use crate::topology_manager::{Ieee1905DeviceData, Ieee1905InterfaceData, UpdateType};
    use crate::TopologyDatabase;
    use pnet::datalink::MacAddr;

    #[tokio::test]
    async fn test_remote_controller_won() {
        let db = TopologyDatabase::new(MacAddr::new(0, 0, 0, 0, 0, 0), "en1".to_string());

        let device_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let device_al_mac = MacAddr::new(0, 0, 0, 0, 0, 2);
        let device_if_mac = MacAddr::new(0, 0, 0, 0, 0, 3);

        let interface = Ieee1905InterfaceData {
            mac: device_if_mac,
            media_type: MediaType::ETHERNET_802_3ab,
            media_type_extra: Default::default(),
            bridging_flag: false,
            bridging_tuple: None,
            vlan: None,
            metric: None,
            phy_rate: None,
            link_availability: None,
            signal_strength_dbm: None,
            non_ieee1905_neighbors: None,
            ieee1905_neighbors: None,
        };
        let device = Ieee1905DeviceData::new(
            device_al_mac,
            device_al_mac,
            Some(device_mac),
            db.local_mac.read().await.clone(),
            Some(vec![interface]),
            None,
        );
        db.update_ieee1905_topology(
            device.clone(),
            UpdateType::DiscoveryReceived,
            None,
            None,
            None,
        )
        .await;

        assert!(db.find_device_by_port(device_mac).await.is_some());
        assert!(db.find_device_by_port(device_al_mac).await.is_some());
        assert!(db.find_device_by_port(device_if_mac).await.is_some());
        assert!(db
            .find_device_by_port(MacAddr::new(0, 0, 0, 0, 0, 4))
            .await
            .is_none());
    }
}
