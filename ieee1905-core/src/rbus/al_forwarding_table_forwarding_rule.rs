use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.
///
pub struct RBus_Al_ForwardingTable_ForwardingRule;

impl RBusProviderTableSync for RBus_Al_ForwardingTable_ForwardingRule {
    type UserData = ();

    fn len(&mut self, _args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        Ok(0)
    }
}

impl RBusProviderGetter for RBus_Al_ForwardingTable_ForwardingRule {
    type UserData = ();

    fn get(&mut self, _args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        Err(RBusError::ElementDoesNotExists)
    }
}
