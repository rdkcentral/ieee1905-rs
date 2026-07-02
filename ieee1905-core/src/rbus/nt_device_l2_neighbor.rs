use crate::rbus::nt_device::RBus_Ieee1905Device_Node;
use crate::rbus::peek_topology_database;
use nom::AsBytes;
use pnet::datalink::MacAddr;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.L2Neighbor.{i}.
/// - LocalInterface
/// - NeighborInterfaceId
/// - BehindInterfaceIds
///
pub struct RBus_NetworkTopology_Ieee1905Device_L2Neighbor;

pub struct L2Neighbor {
    local_interface_index: usize,
    neighbor_interface_mac: MacAddr,
}

impl RBus_NetworkTopology_Ieee1905Device_L2Neighbor {
    pub fn iter<'a>(node: &'a RBus_Ieee1905Device_Node) -> impl Iterator<Item = L2Neighbor> + 'a {
        let interfaces = node.local_interfaces();
        interfaces.enumerate().flat_map(|(index, data)| {
            let neighbors1 = data.non_ieee1905_neighbors.as_deref().unwrap_or_default();
            let neighbors1 = neighbors1.iter().map(move |e| L2Neighbor {
                local_interface_index: index,
                neighbor_interface_mac: *e,
            });

            let neighbors2 = data.ieee1905_neighbors.as_deref().unwrap_or_default();
            let neighbors2 = neighbors2.iter().map(move |e| L2Neighbor {
                local_interface_index: index,
                neighbor_interface_mac: e.neighbor_al_mac,
            });

            std::iter::chain(neighbors1, neighbors2)
        })
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_L2Neighbor {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        Ok(Self::iter(&node).count() as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_L2Neighbor {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(neighbour_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let (node_index, node) = RBus_Ieee1905Device_Node::from(db, args.table_idx)?;
        let mut neighbours = Self::iter(&node);

        let Some(info) = neighbours.nth(neighbour_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"LocalInterface" => {
                let if_index = info.local_interface_index;
                args.property.set(&format!("Device.IEEE1905.AL.0.NetworkTopology.IEEE1905Device.{node_index}.Interface.{if_index}"));
                Ok(())
            }
            b"NeighborInterfaceId" => {
                args.property.set(&info.neighbor_interface_mac.to_string());
                Ok(())
            }
            b"BehindInterfaceIds" => {
                args.property.set("");
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
