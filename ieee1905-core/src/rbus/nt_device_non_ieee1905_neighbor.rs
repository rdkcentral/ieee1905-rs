use crate::rbus::nt_device::RBus_Ieee1905Device_Node;
use crate::rbus::{format_mac_address, peek_topology_database};
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
    pub fn iter_neighbors<'a>(
        node: &'a RBus_Ieee1905Device_Node,
    ) -> impl Iterator<Item = (usize, MacAddr)> + 'a {
        let interfaces = node.local_interfaces();
        interfaces.enumerate().flat_map(|(index, e)| {
            let neighbours = &e.non_ieee1905_neighbors;
            let neighbours = neighbours.as_deref().unwrap_or_default();
            neighbours.iter().map(move |e| (index, *e))
        })
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        let count = Self::iter_neighbors(&node).count();

        Ok(count as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(neighbour_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let (node_index, node) = RBus_Ieee1905Device_Node::from(&db, args.table_idx)?;
        let neighbours = Self::iter_neighbors(&node);

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
