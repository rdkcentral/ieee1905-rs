use crate::rbus::peek_topology_database;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.{i}.IEEE1905Id
///
pub struct RBus_Ieee1905Id;

impl RBusProviderGetter for RBus_Ieee1905Id {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let db = peek_topology_database()?;
        let mac_addr = db.al_mac_address.blocking_read().clone();

        let mac_text = mac_addr.octets().map(|e| format!("{e:02X}")).join("-");
        args.property.set(&mac_text);

        Ok(())
    }
}
