use crate::cmdu::IEEE1905Neighbor;
use crate::rbus::nt_device::RBus_Ieee1905Device_Node;
use crate::rbus::nt_device_ieee1905_neighbor_metric::RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric;
use crate::rbus::peek_topology_database;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.
/// - LocalInterface
/// - NeighborDeviceId
/// - MetricNumberOfEntries
///
pub struct RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor;

pub struct Ieee1905Neighbor<'a> {
    if_index: usize,
    pub neighbor: &'a IEEE1905Neighbor,
}

impl RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor {
    pub fn iter<'a>(
        node: &'a RBus_Ieee1905Device_Node,
    ) -> impl Iterator<Item = Ieee1905Neighbor<'a>> + 'a {
        let interfaces = node.local_interfaces();
        interfaces.enumerate().flat_map(|(if_index, e)| {
            let neighbours = e.ieee1905_neighbors.as_deref().unwrap_or_default();
            neighbours
                .iter()
                .map(move |neighbor| Ieee1905Neighbor { if_index, neighbor })
        })
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        let count = Self::iter(&node).count();
        Ok(count as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor {
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
                let if_index = info.if_index;
                args.property.set(&format!("Device.IEEE1905.AL.0.NetworkTopology.IEEE1905Device.{node_index}.Interface.{if_index}"));
                Ok(())
            }
            b"NeighborInterfaceId" => {
                let mac = info.neighbor.neighbor_al_mac.to_string();
                args.property.set(&mac);
                Ok(())
            }
            b"MetricNumberOfEntries" => {
                let metrics = RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric::collect(
                    &node, &info,
                );
                args.property.set(&(metrics.len() as u32));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
