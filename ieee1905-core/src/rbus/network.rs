use crate::rbus::peek_topology_database;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.Network.
/// - Status
/// - ALNumberOfEntries
///
pub struct RBus_Network;

impl RBusProviderTableSync for RBus_Network {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let _ = args;
        let db = peek_topology_database()?;
        Ok(db.nodes.blocking_read().len() as u32)
    }
}

impl RBusProviderGetter for RBus_Network {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        match args.path_name.as_bytes() {
            b"Status" => {
                args.property.set("Available");
                Ok(())
            }
            b"ALNumberOfEntries" => {
                let db = peek_topology_database()?;
                let value = db.nodes.blocking_read().len() as u32;
                args.property.set(&value);
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
