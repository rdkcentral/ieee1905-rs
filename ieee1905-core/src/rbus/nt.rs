use crate::rbus::nt_device::RBus_NetworkTopology_Ieee1905Device;
use crate::rbus::peek_topology_database;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.NetworkTopology
/// - IEEE1905DeviceNumberOfEntries
///
pub struct RBus_NetworkTopology;

impl RBusProviderGetter for RBus_NetworkTopology {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let db = peek_topology_database()?;

        match args.path_name.as_bytes() {
            b"IEEE1905DeviceNumberOfEntries" => {
                let len = RBus_NetworkTopology_Ieee1905Device::count_rows(&db);
                args.property.set(&(len as u32));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
