use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.Network.
/// - Status
/// - ALNumberOfEntries
///
pub struct RBus_Al_Network;

impl RBusProviderGetter for RBus_Al_Network {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        match args.path_name.as_bytes() {
            b"Status" => {
                args.property.set("Incomplete");
                Ok(())
            }
            b"ALNumberOfEntries" => {
                args.property.set(&0u32);
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
