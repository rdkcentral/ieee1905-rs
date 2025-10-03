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
use tokio::{
    sync::{OnceCell, RwLock},
    task::{spawn, yield_now},
    time::{interval, Duration, Instant},
};
use tracing::debug;
use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    text::{Span, Spans},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Terminal,
};
// use crate::task_registry::TASK_REGISTRY;
// Standard library
use std::{collections::HashMap, io, sync::Arc};
use std::collections::HashSet;
// Internal modules
use crate::{
    cmdu::IEEE1905Neighbor,
    interface_manager::{get_forwarding_interface_mac, get_interfaces},
    //task_registry::TASK_REGISTRY,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateLocal {
    Idle,
    ConvergingLocal,
    ConvergedLocal,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateRemote {
    Idle,
    ConvergingRemote,
    ConvergedRemote,
}

/// Synchronization state of a node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateType {
    LldpUpdate,
    DiscoveryReceived,
    NotificationSent,
    NotificationReceived,
    QuerySent,
    QueryReceived,
    ResponseSent,
    ResponseReceived,
    AutoConfigSearch,
    AutoConfigResponse,
    SDU,
}

pub enum TransmissionEvent {
    SendTopologyQuery(MacAddr),
    SendTopologyResponse(MacAddr),
    SendTopologyNotification(MacAddr),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ieee1905InterfaceData {
    pub mac: MacAddr,
    pub media_type: u16,
    pub bridging_flag: bool,
    pub bridging_tuple: Option<u8>,
    pub vlan: Option<u8>,
    pub metric: Option<u16>,
    pub non_ieee1905_neighbors: Option<Vec<MacAddr>>,
    pub ieee1905_neighbors: Option<Vec<IEEE1905Neighbor>>,
}
impl Ieee1905InterfaceData {
    pub fn new(
        mac: MacAddr,
        media_type: u16,
        bridging_flag: bool,
        bridging_tuple: Option<u8>,
        vlan: Option<u8>,
        metric: Option<u16>,
        non_ieee1905_neighbors: Option<Vec<MacAddr>>,
        ieee1905_neighbors: Option<Vec<IEEE1905Neighbor>>,
    ) -> Self {
        Self {
            mac,
            media_type,
            bridging_flag,
            bridging_tuple,
            vlan,
            metric,
            non_ieee1905_neighbors,
            ieee1905_neighbors,
        }
    }

    pub fn update(
        &mut self,
        new_bridging_flag: Option<bool>,
        new_bridging_tuple: Option<u8>,
        new_vlan: Option<u8>,
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
    pub last_update: UpdateType,
    pub last_seen: Instant,
    pub message_id: Option<u16>,
    pub lldp_neighbor: Option<bool>,
    pub node_state_local: Option<StateLocal>,
    pub node_state_remote: Option<StateRemote>,
}

impl Ieee1905NodeInfo {
    /// **Create a new `Ieee1905NodeInfo` instance**
    pub fn new(
        last_update: UpdateType,
        message_id: Option<u16>,
        lldp_neighbor: Option<bool>,
        node_state_local: Option<StateLocal>,
        node_state_remote: Option<StateRemote>,
    ) -> Self {
        Self {
            last_update,
            last_seen: Instant::now(), // Set current time at creation
            message_id,
            lldp_neighbor,
            node_state_local,
            node_state_remote,
        }
    }

    /// **Update existing `Ieee1905NodeInfo` fields**
    pub fn update(
        &mut self,
        new_state: Option<UpdateType>,
        new_message_id: Option<u16>,
        new_lldp_neighbor: Option<bool>,
        new_node_state_local: Option<StateLocal>,
        new_node_state_remote: Option<StateRemote>,
    ) {
        if let Some(message_type) = new_state {
            self.last_update = message_type;
        }
        if let Some(message_id) = new_message_id {
            self.message_id = Some(message_id);
        }
        if let Some(lldp_neighbor) = new_lldp_neighbor {
            self.lldp_neighbor = Some(lldp_neighbor);
        }
        if let Some(local) = new_node_state_local {
            self.node_state_local = Some(local);
        }
        if let Some(remote) = new_node_state_remote {
            self.node_state_remote = Some(remote);
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
    pub destination_mac: Option<MacAddr>,
    pub local_interface_list: Option<Vec<Ieee1905InterfaceData>>,
    pub registry_role: Option<Role>,
}

impl Ieee1905DeviceData {
    /// **Create a new `Ieee1905DeviceData`**
    pub fn new(
        al_mac: MacAddr,
        destination_mac: Option<MacAddr>,
        local_interface_list: Option<Vec<Ieee1905InterfaceData>>,
        registry_role: Option<Role>,
    ) -> Self {
        Self {
            al_mac,
            destination_mac,
            local_interface_list,
            registry_role,
        }
    }

    /// **Update existing `Ieee1905DeviceData` fields**
    pub fn update(
        &mut self,
        new_destination_mac: Option<MacAddr>,
        new_interfaces: Option<Vec<Ieee1905InterfaceData>>,
    ) {
        if let Some(destination_mac) = new_destination_mac {
            self.destination_mac = Some(destination_mac);
        }
        if let Some(interfaces) = new_interfaces {
            self.local_interface_list = Some(interfaces);
        }
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

pub static TOPOLOGY_DATABASE: OnceCell<Arc<TopologyDatabase>> = OnceCell::const_new();

#[derive(Debug)]
pub struct TopologyDatabase {
    pub al_mac_address: Arc<RwLock<MacAddr>>,
    pub local_mac: Arc<RwLock<MacAddr>>,
    pub local_interface_list: Arc<RwLock<Option<Vec<Ieee1905InterfaceData>>>>,
    pub nodes: Arc<RwLock<HashMap<MacAddr, Ieee1905Node>>>,
    pub interface_name: Arc<RwLock<Option<String>>>,
    pub local_role: Arc<RwLock<Option<Role>>>,
    /// Stores remote controllers that won tiebreak against us
    /// This helps to avoid linear search through all nodes to find remote controllers
    remote_controllers_cache: RwLock<HashSet<MacAddr>>,
}

impl TopologyDatabase {
    /// **Creates a new `TopologyDatabase` instance**
    pub async fn new(al_mac_address: MacAddr, interface_name: String) -> Arc<Self> {
        debug!(al_mac = %al_mac_address, "Database initialized");

        // Get local MAC address from forwarding interface
        let local_mac = Arc::new(RwLock::new(get_forwarding_interface_mac(interface_name.clone()).unwrap()));

        let db = Arc::new(TopologyDatabase {
            al_mac_address: Arc::new(RwLock::new(al_mac_address)), // Wrapped in Arc<RwLock<T>>
            local_mac,
            local_interface_list: Arc::new(RwLock::new(None)),
            nodes: Arc::new(RwLock::new(HashMap::new())),
            interface_name: Arc::new(RwLock::new(Some(interface_name))),
            local_role: Arc::new(RwLock::new(None)),
            remote_controllers_cache: RwLock::default(),
        });

        db.refresh_topology().await;
        db.refresh_interfaces().await;
        db
    }

    /// ** Returns the actual local role
    pub async fn get_actual_local_role(&self) -> Option<Role> {
        let role = self.local_role.read().await.clone()?;
        if role == Role::Registrar {
            // downgrade to an agent when any controller which won a tiebreaker is present
            if !self.remote_controllers_cache.read().await.is_empty() {
                return Some(Role::Enrollee);
            }
        }
        Some(role)
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
    pub async fn get_instance(
        al_mac_address: MacAddr,
        interface_name: String,
    ) -> Arc<TopologyDatabase> {
        TOPOLOGY_DATABASE
            .get_or_init(|| async {
                TopologyDatabase::new(al_mac_address, interface_name).await
            })
            .await
            .clone()
    }
    /// **Retrieves a device node from the database**
    pub async fn get_device(&self, al_mac: MacAddr) -> Option<Ieee1905Node> {
        let nodes = self.nodes.read().await; // Read lock
        nodes.get(&al_mac).cloned() // Clone to return the device node
    }

    /// **Getter for `local_interface_list`**
    pub async fn get_local_interface_list(&self) -> Option<Vec<Ieee1905InterfaceData>> {
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

    pub async fn get_node_states(
        &self,
        al_mac: MacAddr,
    ) -> (Option<StateLocal>, Option<StateRemote>) {
        let nodes = self.nodes.read().await;
        if let Some(node) = nodes.get(&al_mac) {
            (
                node.metadata.node_state_local,
                node.metadata.node_state_remote,
            )
        } else {
            (None, None)
        }
    }

    pub async fn has_remote_controllers(&self) -> bool {
        !self.remote_controllers_cache.read().await.is_empty()
    }

    async fn add_remote_controller(&self, al_mac: MacAddr) -> bool {
        let local_al_mac = *self.al_mac_address.read().await;
        if !Self::tiebreaker(al_mac, local_al_mac) {
            return false;
        }
        let mut remote_controllers = self.remote_controllers_cache.write().await;
        remote_controllers.insert(al_mac);
        true
    }

    async fn remove_remote_controller(&self, al_mac: MacAddr) {
        self.remote_controllers_cache.write().await.remove(&al_mac);
    }

    pub async fn refresh_topology(self: &Arc<Self>) {
        let this = self.clone();
        let _task_handle = spawn(async move {
            let mut ticker = interval(Duration::from_secs(5)); // Runs every 5 seconds

            loop {
                ticker.tick().await; // Wait for the next tick

                let mut nodes = this.nodes.write().await;
                let mut removed_nodes = Vec::new();
                let now = Instant::now();

                nodes.retain(|al_mac, node| {
                    if !Self::check_if_node_should_be_removed(*al_mac, node, now) {
                        return true;
                    }
                    removed_nodes.push(*al_mac);
                    false
                });

                if nodes.is_empty() {
                    debug!("No nodes in the topology, waiting for updates...");
                }
                drop(nodes); // avoid potential deadlock (nodes+remote_controller)

                // TODO change to extract_if to avoid allocations after upgrade to MSRV 1.88
                for al_mac in removed_nodes {
                    this.remove_remote_controller(al_mac).await;
                }
            }
        });
        //TASK_REGISTRY.lock().await.push(task_handle);
    }

    fn check_if_node_should_be_removed(al_mac: MacAddr, node: &Ieee1905Node, now: Instant) -> bool {
        const CONVERGE_TIMEOUT: Duration = Duration::from_secs(40);
        const INACTIVE_TIMEOUT: Duration = Duration::from_secs(60);

        let elapsed = now.duration_since(node.metadata.last_seen);

        // **Remove nodes stuck in Converging state for too long
        if node.metadata.node_state_local == Some(StateLocal::ConvergingLocal) && elapsed >= CONVERGE_TIMEOUT {
            debug!(
                al_mac = ?al_mac,
                state = ?node.metadata.last_update,
                "Removing node stuck in local convergence for too long"
            );
            return true;
        }

        // **Remove nodes stuck in Converging state for too long
        if node.metadata.node_state_remote == Some(StateRemote::ConvergingRemote) && elapsed >= CONVERGE_TIMEOUT {
            debug!(
                al_mac = ?al_mac,
                state = ?node.metadata.last_update,
                "Removing node stuck in remote convergence for too long"
            );
            return true;
        }

        // **Remove nodes that have been inactive for too long
        if elapsed >= INACTIVE_TIMEOUT {
            debug!(al_mac = ?al_mac, "Removing node due to timeout");
            return true;
        }

        debug!(
            al_mac = ?al_mac,
            elapsed_time = elapsed.as_secs_f64(),
            "Node Last Seen"
        );
        false // Keep the node
    }

    pub async fn refresh_interfaces(&self) {
        let local_interfaces = Arc::clone(&self.local_interface_list);
        let interface_name = Arc::clone(&self.interface_name);
        let forwarding_mac = Arc::clone(&self.local_mac);

        let _task_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(100));

            loop {
                interval.tick().await;

                match tokio::task::spawn_blocking(get_interfaces).await {
                    Ok(interfaces) => {
                        let mut list = local_interfaces.write().await;

                        if interfaces.is_empty() {
                            *list = None;
                            tracing::debug!("No interfaces found — set to None");
                        } else {
                            *list = Some(interfaces);
                            tracing::debug!("Updated local interfaces");
                        }
                    }
                    Err(e) => {
                        tracing::error!("Interface scan task panicked: {:?}", e);
                    }
                }
                if let Some(int_name) = interface_name.read().await.clone() {
                    let mut mac_lock = forwarding_mac.write().await;
                    *mac_lock = get_forwarding_interface_mac(int_name).unwrap();
                }
            }
        });
        //TASK_REGISTRY.lock().await.push(task_handle);
    }

    /// Tie breaker function in case we need to give priority in case of collision
    /// Returns `true` if left wins
    pub fn tiebreaker(left: MacAddr, right: MacAddr) -> bool {
        let local_last = left.5;
        let remote_last = right.5;
        local_last < remote_last
    }

    /// **Adds or updates a node in the topology database**
    pub async fn update_ieee1905_topology(
        &self,
        device_data: Ieee1905DeviceData,
        operation: UpdateType,
        msg_id: Option<u16>,
        lldp_neighbor: Option<bool>,
    ) -> TransmissionEvent {
        let al_mac = device_data.al_mac;
        let event;
        //TODO: use new update types.
        tracing::debug!("WAITING for write lock");
        {
            let mut nodes = self.nodes.write().await;
            tracing::debug!("ACQUIRED write lock");

            event = match nodes.get_mut(&al_mac) {
                Some(node) => {
                    tracing::debug!(al_mac = ?al_mac, operation = ?operation, "Updating existing node");

                    match operation {
                        UpdateType::DiscoveryReceived => {
                            let local_state = node.metadata.node_state_local;
                            let remote_state = node.metadata.node_state_remote;

                            node.metadata
                                .update(Some(operation), msg_id, None, None, None);

                            if matches!(
                                (local_state, remote_state),
                                (Some(StateLocal::Idle), Some(_))
                            ) {
                                TransmissionEvent::SendTopologyQuery(al_mac)
                            } else {
                                TransmissionEvent::None
                            }
                        }
                        UpdateType::NotificationReceived => {
                            let local_state = node.metadata.node_state_local;
                            let remote_state = node.metadata.node_state_remote;
                            if matches!(
                                (local_state, remote_state),
                                (Some(StateLocal::ConvergedLocal), Some(_))
                            ) {
                                node.metadata
                                    .update(Some(operation), msg_id, None, None, None);
                                TransmissionEvent::SendTopologyQuery(al_mac)
                            } else {
                                TransmissionEvent::None
                            }
                        }
                        UpdateType::QueryReceived => {
                            let local_state = node.metadata.node_state_local;
                            let remote_state = node.metadata.node_state_remote;

                            if matches!((local_state, remote_state), (Some(_), Some(_))) {
                                node.metadata.update(
                                    Some(operation),
                                    msg_id,
                                    None,
                                    None,
                                    Some(StateRemote::ConvergingRemote),
                                );
                                tracing::debug!("Event: Send Topology Response");
                                TransmissionEvent::SendTopologyResponse(al_mac)
                            } else {
                                tracing::debug!("Conditions not met: No transmission needed after QueryReceived");
                                TransmissionEvent::None
                            }
                        }

                        UpdateType::ResponseReceived => {
                            let local_state = node.metadata.node_state_local;

                            if matches!(local_state, Some(StateLocal::ConvergingLocal)) {
                                node.metadata.update(
                                    Some(operation),
                                    msg_id,
                                    None,
                                    Some(StateLocal::ConvergedLocal),
                                    None,
                                );

                                tracing::debug!(
                                    current_local_interface_list = ?node.device_data.local_interface_list,
                                    new_local_interface_list = ?device_data.local_interface_list,
                                    "Comparing local_interface_list"
                                );

                                if node.device_data.registry_role != device_data.registry_role {
                                    debug!("Device data changed registry role");
                                    node.device_data.registry_role = device_data.registry_role;

                                    if device_data.registry_role == Some(Role::Registrar) {
                                        self.add_remote_controller(al_mac).await;
                                    } else {
                                        self.remove_remote_controller(al_mac).await;
                                    }
                                }

                                if node.device_data.local_interface_list != device_data.local_interface_list {
                                    tracing::debug!("Device data changed local_interface_list)");

                                    node.device_data.update(
                                        device_data.destination_mac,
                                        device_data.local_interface_list,
                                    );

                                    let multicast_mac =
                                        MacAddr::new(0x01, 0x80, 0xC2, 0x00, 0x00, 0x13);
                                    tracing::debug!("Event: Send Topology Notification");
                                    TransmissionEvent::SendTopologyNotification(multicast_mac)
                                } else {
                                    tracing::debug!(
                                        "Device data unchanged — no transmission needed"
                                    );
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
                            node.metadata.update(
                                Some(operation),
                                msg_id,
                                None,
                                Some(StateLocal::ConvergingLocal),
                                None,
                            );
                            TransmissionEvent::None
                        }
                        UpdateType::ResponseSent => {
                            node.metadata.update(
                                Some(operation),
                                msg_id,
                                None,
                                None,
                                Some(StateRemote::ConvergedRemote),
                            );
                            TransmissionEvent::None
                        }
                        UpdateType::LldpUpdate => {
                            node.metadata.update(
                                Some(operation),
                                msg_id,
                                lldp_neighbor,
                                None,
                                None,
                            );
                            tracing::debug!(al_mac = ?al_mac, lldp_neighbor = ?lldp_neighbor, "Updated LLDP neighbor status");
                            TransmissionEvent::None
                            //If needed we can indicate here a notification event to update topology data base in al neighbors but for now it is not needed
                            //initial DB snapshot covers current uses cases for RDK-B but we can update this part if needed in the future
                        }
                        UpdateType::AutoConfigResponse => {
                            let local_state = node.metadata.node_state_local;
                            let remote_state = node.metadata.node_state_remote;
                            if matches!(
                                (local_state, remote_state),
                                (
                                    Some(StateLocal::ConvergedLocal),
                                    Some(StateRemote::ConvergedRemote)
                                )
                            ) {
                                node.metadata
                                    .update(Some(operation), msg_id, None, None, None);
                            }
                            TransmissionEvent::None
                        }
                        UpdateType::AutoConfigSearch => {
                            let local_state = node.metadata.node_state_local;
                            let remote_state = node.metadata.node_state_remote;
                            if matches!(
                                (local_state, remote_state),
                                (
                                    Some(StateLocal::ConvergedLocal),
                                    Some(StateRemote::ConvergedRemote)
                                )
                            ) {
                                node.metadata
                                    .update(Some(operation), msg_id, None, None, None);
                            }
                            TransmissionEvent::None
                        }
                        _ => {
                            tracing::warn!(al_mac = ?al_mac, operation = ?operation, "Unhandled update for existing node");
                            TransmissionEvent::None
                        }
                    }
                }
                None => {
                    tracing::debug!(al_mac = ?al_mac, operation = ?operation, "Node not found — inserting");

                    let mut new_node = Ieee1905Node {
                        metadata: Ieee1905NodeInfo {
                            last_update: operation,
                            last_seen: Instant::now(),
                            message_id: msg_id,
                            lldp_neighbor: Some(false),
                            node_state_local: None,
                            node_state_remote: None,
                        },
                        device_data,
                    };

                    match operation {
                        UpdateType::DiscoveryReceived => {
                            new_node.metadata.node_state_local = Some(StateLocal::Idle);
                            new_node.metadata.node_state_remote = Some(StateRemote::Idle);
                            nodes.insert(al_mac, new_node);
                            tracing::debug!(al_mac = ?al_mac, "Inserted node from Discovery");
                            return TransmissionEvent::SendTopologyQuery(al_mac);
                        }
                        UpdateType::QueryReceived => {
                            new_node.metadata.node_state_local = Some(StateLocal::Idle);
                            new_node.metadata.node_state_remote = Some(StateRemote::ConvergingRemote);
                            nodes.insert(al_mac, new_node);
                            tracing::debug!(al_mac = ?al_mac, "Inserted node from query");
                            return TransmissionEvent::SendTopologyResponse(al_mac);
                        }
                        _ => {
                            tracing::debug!(al_mac = ?al_mac, operation = ?operation, "Insertion skipped — unsupported operation");
                        }
                    }

                    TransmissionEvent::None
                }
            };
        }

        tracing::debug!("Lock released — function continues safely");
        event
    }
    pub async fn start_topology_cli(self: Arc<Self>) -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        loop {
            let local_mac = self.al_mac_address.read().await.to_string();

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
                    .split(f.size());

                // ─────────────────────── BLOQUE 1: TOPOLOGY MANAGER
                let block1 = Block::default()
                    .title("TOPOLOGY MANAGER")
                    .borders(Borders::ALL);

                let mut lines = vec![
                    Spans::from(vec![Span::raw(format!("Local AL MAC: {local_mac}"))]),
                    Spans::from(vec![Span::raw("Interfaces:")]),
                ];

                if let Some(interface_list) = &interfaces {
                    for iface in interface_list {
                        lines.push(Spans::from(vec![Span::raw(format!(
                            "- MAC: {}, MediaType: {}",
                            iface.mac, iface.media_type,
                        ))]));
                    }
                } else {
                    lines.push(Spans::from(vec![Span::raw("- No interfaces available")]));
                }

                let paragraph1 = Paragraph::new(lines)
                    .block(block1)
                    .wrap(tui::widgets::Wrap { trim: true });

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
                        .map(|l| l.to_string())
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

                let table = Table::new(rows)
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
                    .widths(&[
                        Constraint::Length(20),
                        Constraint::Length(25),
                        Constraint::Length(25),
                        Constraint::Length(15),
                        Constraint::Length(20),
                        Constraint::Length(10),
                        Constraint::Length(20),
                        Constraint::Length(15),
                    ])
                    .column_spacing(1);

                f.render_widget(table, chunks[1]);

                //Footer
                let block3 = Block::default().borders(Borders::ALL);
                let paragraph3 =
                    Paragraph::new(vec![Spans::from(vec![Span::raw("Press 'q' to quit.")])])
                        .block(block3)
                        .wrap(tui::widgets::Wrap { trim: true });

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
    use crate::topology_manager::{Ieee1905DeviceData, Role, UpdateType};
    use crate::TopologyDatabase;
    use pnet::util::MacAddr;

    #[tokio::test]
    async fn test_remote_controller_won() {
        let db = TopologyDatabase::new(MacAddr::from([0, 0, 0, 0, 0, 2]), "eth0".to_string()).await;

        assert!(!db.has_remote_controllers().await);

        db.set_local_role(Some(Role::Enrollee)).await;
        assert_eq!(db.get_actual_local_role().await, Some(Role::Enrollee));

        db.set_local_role(Some(Role::Registrar)).await;
        assert_eq!(db.get_actual_local_role().await, Some(Role::Registrar));

        let device_mac = MacAddr::from([0, 0, 0, 0, 0, 1]);
        let device = Ieee1905DeviceData::new(device_mac, None, None, None);
        db.update_ieee1905_topology(device.clone(), UpdateType::DiscoveryReceived, None, None).await;
        let device = Ieee1905DeviceData::new(device_mac, None, None, None);
        db.update_ieee1905_topology(device.clone(), UpdateType::QuerySent, None, None).await;
        let device = Ieee1905DeviceData::new(device_mac, None, None, Some(Role::Registrar));
        db.update_ieee1905_topology(device.clone(), UpdateType::ResponseReceived, None, None).await;

        assert!(db.has_remote_controllers().await);
        assert_ne!(db.get_actual_local_role().await, Some(Role::Registrar));
    }

    #[tokio::test]
    async fn test_remote_controller_lost() {
        let db = TopologyDatabase::new(MacAddr::from([0, 0, 0, 0, 0, 2]), "eth0".to_string()).await;

        assert!(!db.has_remote_controllers().await);

        db.set_local_role(Some(Role::Enrollee)).await;
        assert_eq!(db.get_actual_local_role().await, Some(Role::Enrollee));

        db.set_local_role(Some(Role::Registrar)).await;
        assert_eq!(db.get_actual_local_role().await, Some(Role::Registrar));

        let device_mac = MacAddr::from([0, 0, 0, 0, 0, 3]);
        let device = Ieee1905DeviceData::new(device_mac, None, None, None);
        db.update_ieee1905_topology(device.clone(), UpdateType::DiscoveryReceived, None, None).await;
        let device = Ieee1905DeviceData::new(device_mac, None, None, None);
        db.update_ieee1905_topology(device.clone(), UpdateType::QuerySent, None, None).await;
        let device = Ieee1905DeviceData::new(device_mac, None, None, Some(Role::Registrar));
        db.update_ieee1905_topology(device.clone(), UpdateType::ResponseReceived, None, None).await;

        assert!(!db.has_remote_controllers().await);
        assert_eq!(db.get_actual_local_role().await, Some(Role::Registrar));
    }
}
