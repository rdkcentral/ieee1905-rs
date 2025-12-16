use crate::rbus::nt_device_bridge::RBus_NetworkTopology_Ieee1905Device_BridgingTuple;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTupleNumberOfEntries
///
pub struct RBus_NetworkTopology_Ieee1905Device_BridgingTupleNumberOfEntries;

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_BridgingTupleNumberOfEntries {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(node_index) = args.table_idx.get(0).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let node_index = node_index as usize;
        let tuples = RBus_NetworkTopology_Ieee1905Device_BridgingTuple::get_tuples(node_index)?;
        args.property.set(&(tuples.len() as u32));
        Ok(())
    }
}
