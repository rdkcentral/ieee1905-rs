use crate::rbus::peek_topology_database;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Id
///
pub struct RBus_NetworkTopology_Ieee1905Device_Ieee1905Id;

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_Ieee1905Id {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let lock = peek_topology_database()?.nodes.blocking_read();

        let Some(index) = args.table_idx.get(0).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };
        let Some(node) = lock.get_index(index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let mac_text = node.0.octets().map(|e| format!("{e:02X}")).join("-");
        args.property.set(&mac_text);
        Ok(())
    }
}
