use crate::rbus::{format_mac_address, peek_topology_database};
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.{i}.
/// - IEEE1905Id
/// - InterfaceNumberOfEntries
///
pub struct RBus_Al_Device;

impl RBusProviderGetter for RBus_Al_Device {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let db = peek_topology_database()?;

        match args.path_name.as_bytes() {
            b"IEEE1905Id" => {
                args.property.set(&format_mac_address(&db.al_mac_address));
                Ok(())
            }
            b"InterfaceNumberOfEntries" => {
                let interfaces = db.local_interface_list.blocking_read();
                let len = interfaces.as_deref().unwrap_or_default().len();
                args.property.set(&(len as u32));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
