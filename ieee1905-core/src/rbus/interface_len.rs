use crate::rbus::peek_topology_database;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.InterfaceNumberOfEntries
///
pub struct RBus_InterfaceNumberOfEntries;

impl RBusProviderGetter for RBus_InterfaceNumberOfEntries {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let db = peek_topology_database()?;
        let interfaces = db.local_interface_list.blocking_read();
        let len = interfaces.as_deref().unwrap_or_default().len();
        args.property.set(&(len as u32));
        Ok(())
    }
}
