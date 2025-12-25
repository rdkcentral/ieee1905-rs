use crate::rbus::{format_mac_address, format_media_type, peek_topology_database};
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.Interface.{i}.
/// - InterfaceId
/// - MediaType
///
pub struct RBus_Interface;

impl RBusProviderTableSync for RBus_Interface {
    type UserData = ();

    fn len(&mut self, _args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let db = peek_topology_database()?;
        let interfaces = db.local_interface_list.blocking_read();
        Ok(interfaces.as_deref().unwrap_or_default().len() as u32)
    }
}

impl RBusProviderGetter for RBus_Interface {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(if_index) = args.table_idx.get(0) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let interfaces = db.local_interface_list.blocking_read();
        let interfaces = interfaces.as_deref().unwrap_or_default();
        let Some(interface) = interfaces.get(*if_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"InterfaceId" => {
                args.property.set(&format_mac_address(&interface.mac));
                Ok(())
            }
            b"MediaType" => {
                args.property.set(format_media_type(interface.media_type));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
