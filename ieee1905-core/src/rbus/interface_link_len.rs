use crate::rbus::interface_link::RBus_InterfaceLink;
use crate::rbus::peek_topology_database;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.Interface.{i}.LinkNumberOfEntries
///
pub struct RBus_InterfaceLinksLen;

impl RBusProviderGetter for RBus_InterfaceLinksLen {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let db = peek_topology_database()?;
        let links = RBus_InterfaceLink::get_links(&db, args.table_idx)?;

        args.property.set(&(links.len() as u32));
        Ok(())
    }
}
