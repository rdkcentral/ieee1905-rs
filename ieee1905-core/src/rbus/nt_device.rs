use crate::rbus::peek_topology_database;
use rbus_core::RBusError;
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.
///
pub struct RBus_NetworkTopology_Ieee1905Device;

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let _ = args;
        Ok(peek_topology_database()?.nodes.blocking_read().len() as u32)
    }
}
