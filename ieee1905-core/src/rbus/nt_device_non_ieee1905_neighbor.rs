use crate::rbus::{format_mac_address, peek_topology_database};
use crate::topology_manager::Ieee1905Node;
use indexmap::IndexMap;
use nom::AsBytes;
use pnet::datalink::MacAddr;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}.
/// - LocalInterface
/// - NeighborInterfaceId
///
pub struct RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor;

impl RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor {
    pub fn iter_neighbors_by_node(
        nodes: &IndexMap<MacAddr, Ieee1905Node>,
        node_index: usize,
    ) -> Result<impl Iterator<Item = (usize, MacAddr)> + '_, RBusError> {
        let Some((_, node)) = nodes.get_index(node_index) else {
            return Err(RBusError::ElementDoesNotExists);
        };
        Ok(Self::iter_neighbors(node))
    }

    pub fn iter_neighbors(node: &Ieee1905Node) -> impl Iterator<Item = (usize, MacAddr)> + '_ {
        let interfaces = &node.device_data.local_interface_list;
        let interfaces = interfaces.as_deref().unwrap_or_default();

        interfaces.iter().enumerate().flat_map(|(index, e)| {
            let neighbours = &e.non_ieee1905_neighbors;
            let neighbours = neighbours.as_deref().unwrap_or_default();
            neighbours.iter().map(move |e| (index, *e))
        })
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let Some(node_index) = args.table_idx.get(0).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let nodes = db.nodes.blocking_read();
        let count = Self::iter_neighbors_by_node(&nodes, node_index as usize)?.count();

        Ok(count as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(node_index) = args.table_idx.get(0).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };
        let Some(neighbour_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let nodes = db.nodes.blocking_read();
        let neighbours = Self::iter_neighbors_by_node(&nodes, node_index as usize)?;

        let Some((if_index, neighbour)) = neighbours.skip(neighbour_index as usize).next() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"LocalInterface" => {
                args.property.set(&format!("Device.IEEE1905.AL.0.NetworkTopology.IEEE1905Device.{node_index}.Interface.{if_index}"));
                Ok(())
            }
            b"NeighborInterfaceId" => {
                args.property.set(&format_mac_address(&neighbour));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
