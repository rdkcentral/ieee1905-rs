use crate::rbus::peek_topology_database;
use indexmap::IndexMap;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}.InterfaceList
///
pub struct RBus_NetworkTopology_Ieee1905Device_BridgingTuple_InterfaceList;

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_BridgingTuple_InterfaceList {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let lock = peek_topology_database()?.nodes.blocking_read();

        let Some(device_index) = args.table_idx.get(0).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };
        let Some(tuple_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };
        let Some(node) = lock.get_index(device_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };
        let Some(interfaces) = node.1.device_data.local_interface_list.as_ref() else {
            return Ok(());
        };

        let mut tuples = IndexMap::<u8, Vec<_>>::new();
        for (index, interface) in interfaces.iter().enumerate() {
            if !interface.bridging_flag {
                continue;
            }
            let tuple = interface.bridging_tuple.unwrap_or_default();
            tuples.entry(tuple).or_default().push(index);
        }

        let Some((_, interfaces)) = tuples.get_index(tuple_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let mut interface_list = String::new();
        let mut separator = "";
        for if_index in interfaces {
            let value = format!("Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{device_index}.Interface.{if_index}");
            interface_list.push_str(separator);
            interface_list.push_str(&value);
            separator = ",";
        }
        args.property.set(&interface_list);
        Ok(())
    }
}
