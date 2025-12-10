use crate::rbus::peek_topology_database;
use rbus_core::RBusError;
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};
use std::collections::HashSet;

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}.
///
pub struct RBus_NetworkTopology_Ieee1905Device_BridgingTuple;

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_BridgingTuple {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let lock = peek_topology_database()?.nodes.blocking_read();

        let Some(node_index) = args.table_idx.get(0).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };
        let Some(node) = lock.get_index(node_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };
        let Some(interfaces) = node.1.device_data.local_interface_list.as_ref() else {
            return Ok(0);
        };

        let mut tuples = HashSet::new();
        for interface in interfaces.iter() {
            if interface.bridging_flag {
                tuples.insert(interface.bridging_tuple.unwrap_or_default());
            }
        }

        Ok(tuples.len() as u32)
    }
}
