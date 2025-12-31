use crate::rbus::peek_topology_database;
use crate::topology_manager::Ieee1905Node;
use indexmap::IndexMap;
use rbus_core::RBusError;
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}.
///
pub struct RBus_NetworkTopology_Ieee1905Device_BridgingTuple;

impl RBus_NetworkTopology_Ieee1905Device_BridgingTuple {
    pub fn get_tuples(node_index: usize) -> Result<IndexMap<u32, Vec<usize>>, RBusError> {
        let lock = peek_topology_database()?.nodes.blocking_read();

        let Some(node) = lock.get_index(node_index) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        Self::get_tuples_from_node(&node.1)
    }

    pub fn get_tuples_from_node(
        node: &Ieee1905Node,
    ) -> Result<IndexMap<u32, Vec<usize>>, RBusError> {
        let Some(interfaces) = node.device_data.local_interface_list.as_ref() else {
            return Ok(IndexMap::new());
        };

        let mut tuples = IndexMap::<u32, Vec<_>>::new();
        for (index, interface) in interfaces.iter().enumerate() {
            if !interface.bridging_flag {
                continue;
            }
            let tuple = interface.bridging_tuple.unwrap_or_default();
            tuples.entry(tuple).or_default().push(index);
        }
        Ok(tuples)
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_BridgingTuple {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let Some(node_index) = args.table_idx.get(0).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let node_index = node_index as usize;
        let tuples = Self::get_tuples(node_index)?;
        Ok(tuples.len() as u32)
    }
}
