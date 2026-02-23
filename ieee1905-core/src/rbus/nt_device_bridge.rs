use crate::rbus::nt_device::RBus_Ieee1905Device_Node;
use crate::rbus::peek_topology_database;
use indexmap::IndexMap;
use rbus_core::RBusError;
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}.
///
pub struct RBus_NetworkTopology_Ieee1905Device_BridgingTuple;

impl RBus_NetworkTopology_Ieee1905Device_BridgingTuple {
    pub fn get_tuples(node: &RBus_Ieee1905Device_Node) -> IndexMap<u32, Vec<usize>> {
        let mut tuples = IndexMap::<u32, Vec<_>>::new();
        for (index, interface) in node.local_interfaces().enumerate() {
            if !interface.bridging_flag {
                continue;
            }
            let tuple = interface.bridging_tuple.unwrap_or_default();
            tuples.entry(tuple).or_default().push(index);
        }
        tuples
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_BridgingTuple {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(&db, args.table_idx)?.1;
        let tuples = Self::get_tuples(&node);
        Ok(tuples.len() as u32)
    }
}
