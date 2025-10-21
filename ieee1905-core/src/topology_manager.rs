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
use tracing::{debug, warn};
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

// Internal modules
use crate::{
    cmdu::IEEE1905Neighbor,
    interface_manager::{get_forwarding_interface_mac, get_interfaces},
    //task_registry::TASK_REGISTRY,
};
use crate::lldpdu::PortId;

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
    pub lldp_neighbor: Option<PortId>,
    pub node_state_local: Option<StateLocal>,
    pub node_state_remote: Option<StateRemote>,
}

impl Ieee1905NodeInfo {
    /// **Create a new `Ieee1905NodeInfo` instance**
    pub fn new(
        last_update: UpdateType,
        message_id: Option<u16>,
        lldp_neighbor: Option<PortId>,
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
        new_lldp_neighbor: Option<PortId>,
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
    pub fn has_changed(&self, other: &Self) -> bool {
        self.local_interface_list != other.local_interface_list
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

#[derive(Debug, Clone)]
pub struct TopologyDatabase {
    pub al_mac_address: Arc<RwLock<MacAddr>>,
    pub local_mac: Arc<RwLock<MacAddr>>,
    pub local_interface_list: Arc<RwLock<Option<Vec<Ieee1905InterfaceData>>>>,
    pub nodes: Arc<RwLock<HashMap<MacAddr, Ieee1905Node>>>,
    pub interface_name: Arc<RwLock<Option<String>>>,
    pub local_role: Arc<RwLock<Option<Role>>>,
}

impl TopologyDatabase {
    /// **Creates a new `TopologyDatabase` instance**
    pub async fn new(al_mac_address: MacAddr, interface_name: String) -> Self {
        debug!(al_mac = %al_mac_address, "Database initialized");

        // TODO singletons initialization must not be failable. this db should be
        //  initialized eagerly from main, and propagated as a dependency

        // Get local MAC address from forwarding interface
        let local_mac = Arc::new(RwLock::new(get_forwarding_interface_mac(interface_name.clone()).unwrap()));

        let db = TopologyDatabase {
            al_mac_address: Arc::new(RwLock::new(al_mac_address)), // Wrapped in Arc<RwLock<T>>
            local_mac,
            local_interface_list: Arc::new(RwLock::new(None)),
            nodes: Arc::new(RwLock::new(HashMap::new())),
            interface_name: Arc::new(RwLock::new(Some(interface_name))),
            local_role: Arc::new(RwLock::new(None)),
        };

        db.refresh_topology().await;
        db.refresh_interfaces().await;
        db
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
    pub async fn get_instance(
        al_mac_address: MacAddr,
        interface_name: String,
    ) -> Arc<TopologyDatabase> {
        TOPOLOGY_DATABASE
            .get_or_init(|| async {
                Arc::new(TopologyDatabase::new(al_mac_address, interface_name).await)
            })
            .await
            .clone()
    }

    /// **Retrieves a device node from the database**
    pub async fn get_device(&self, al_mac: MacAddr) -> Option<Ieee1905Node> {
        let nodes = self.nodes.read().await; // Read lock
        nodes.get(&al_mac).cloned() // Clone to return the device node
    }

    /// **Retrieves a device node from the database**
    pub async fn find_device_by_port(&self, mac: MacAddr) -> Option<Ieee1905Node> {
        let nodes = self.nodes.read().await;
        nodes.values().find(|node| {
            if node.device_data.destination_mac == Some(mac) {
                return true;
            }
            node.device_data.local_interface_list.as_ref().is_some_and(|interfaces| {
                interfaces.iter().any(|e| e.mac == mac)
            })
        }).cloned()
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

    pub async fn refresh_topology(&self) {
        let nodes_clone = Arc::clone(&self.nodes);
        let _task_handle = spawn(async move {
            let mut ticker = interval(Duration::from_secs(5)); // Runs every 5 seconds

            loop {
                ticker.tick().await; // Wait for the next tick
                let mut nodes = nodes_clone.write().await;
                let now = Instant::now();

                nodes.retain(|al_mac, node| {
                    let elapsed = now.duration_since(node.metadata.last_seen);

                    // **Remove nodes stuck in Converging state for 5+ seconds**
                    if matches!(
                        node.metadata.node_state_local,
                        Some(StateLocal::ConvergingLocal)
                    ) && elapsed >= Duration::from_secs(40)
                    {
                        tracing::debug!(
                            al_mac = ?al_mac,
                            state = ?node.metadata.last_update,
                            "Removing node stuck in local convergence for too long"
                        );
                        return false; // **Remove from database**
                    }
                    if matches!(
                        node.metadata.node_state_remote,
                        Some(StateRemote::ConvergingRemote)
                    ) && elapsed >= Duration::from_secs(40)
                    {
                        tracing::debug!(
                            al_mac = ?al_mac,
                            state = ?node.metadata.last_update,
                            "Removing node stuck in remote convergence for too long"
                        );
                        return false; // **Remove from database**
                    }
                    // **Remove nodes that have been inactive for 30+ seconds**
                    if elapsed >= Duration::from_secs(60) {
                        tracing::debug!(al_mac = ?al_mac, "Removing node due to timeout");
                        return false; // **Remove from database**
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
        });
        //TASK_REGISTRY.lock().await.push(task_handle);
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
                    match get_forwarding_interface_mac(int_name) {
                        Some(e) => *forwarding_mac.write().await = e,
                        None => warn!("Failed to fetch forwarding mac address"),
                    }
                }
            }
        });
        //TASK_REGISTRY.lock().await.push(task_handle);
    }

    /// Tie breaker function in case we need to give priority in case of collision
    pub async fn tiebreaker(&self, remote_al_mac: MacAddr) -> bool {
        let local_mac = *self.al_mac_address.read().await;
        let local_last = local_mac.5;
        let remote_last = remote_al_mac.5;

        local_last < remote_last
    }
    /// **Adds or updates a node in the topology database**
    pub async fn update_ieee1905_topology(
        &self,
        device_data: Ieee1905DeviceData,
        operation: UpdateType,
        msg_id: Option<u16>,
        lldp_neighbor: Option<PortId>,
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

                                if node.device_data.has_changed(&device_data) {
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
                                lldp_neighbor.clone(),
                                None,
                                None,
                            );
                            debug!(al_mac = ?al_mac, lldp_neighbor = ?lldp_neighbor, "Updated LLDP neighbor status");
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
                            lldp_neighbor,
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
                            new_node.metadata.node_state_remote =
                                Some(StateRemote::ConvergingRemote);
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
                        Constraint::Length(20),
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
