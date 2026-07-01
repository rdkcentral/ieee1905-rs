use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.ForwardingTable.
/// - SetForwardingEnabled
/// - ForwardingRuleNumberOfEntries
///
pub struct RBus_Al_ForwardingTable;

impl RBusProviderGetter for RBus_Al_ForwardingTable {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        match args.path_name.as_bytes() {
            b"SetForwardingEnabled" => {
                args.property.set(&false);
                Ok(())
            }
            b"ForwardingRuleNumberOfEntries" => {
                args.property.set(&0u32);
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
