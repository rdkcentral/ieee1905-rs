use crate::rbus::nt_device::RBus_Ieee1905Device_Node;
use crate::rbus::nt_device_bridge::RBus_NetworkTopology_Ieee1905Device_BridgingTuple;
use crate::rbus::peek_topology_database;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}.InterfaceList
///
pub struct RBus_NetworkTopology_Ieee1905Device_BridgingTuple_InterfaceList;

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_BridgingTuple_InterfaceList {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(tuple_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let (node_index, node) = RBus_Ieee1905Device_Node::from(&db, args.table_idx)?;
        let tuples = RBus_NetworkTopology_Ieee1905Device_BridgingTuple::get_tuples(&node);

        let Some((_, interfaces)) = tuples.get_index(tuple_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let mut interface_list = String::new();
        let mut separator = "";
        for if_index in interfaces {
            interface_list.push_str(separator);
            interface_list.push_str(&format!(
                "Device.IEEE1905.AL.0.NetworkTopology.IEEE1905Device.{node_index}.Interface.{if_index}"
            ));
            separator = ",";
        }

        args.property.set(&interface_list);
        Ok(())
    }
}
