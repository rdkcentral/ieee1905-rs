use crate::TopologyDatabase;
use rbus::{RBusDataElementGet, RBusError, RBusProperty};

///
/// Device.IEEE1905.AL.{i}.IEEE1905Id
///
pub struct RBus_Ieee1905Id;

impl RBusDataElementGet for RBus_Ieee1905Id {
    fn get(property: &RBusProperty) -> Result<(), RBusError> {
        let mac_addr = TopologyDatabase::peek_instance_sync()
            .map(|e| e.al_mac_address.blocking_read().clone())
            .unwrap_or_default();

        let mac_text = mac_addr.octets().map(|e| format!("{e:02X}")).join("-");
        property.set(&mac_text);

        Ok(())
    }
}
