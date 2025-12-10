use crate::TopologyDatabase;
use rbus::{RBusDataElementGet, RBusError, RBusProperty};
use sscanf::sscanf;

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Id
///
pub struct RBus_NetworkTopology_Ieee1905Device_Ieee1905Id;

impl RBusDataElementGet for RBus_NetworkTopology_Ieee1905Device_Ieee1905Id {
    fn get(property: &RBusProperty) -> Result<(), RBusError> {
        let name = property.get_name().to_string_lossy();
        let result = sscanf!(
            name,
            "Device.IEEE1905.AL.{u32}.NetworkTopology.IEEE1905Device.{usize}.IEEE1905Id"
        );

        let Ok((_, index)) = result else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let mac_addr = TopologyDatabase::peek_instance_sync()
            .and_then(|e| e.nodes.blocking_read().keys().skip(index).cloned().next())
            .unwrap_or_default();

        let mac_text = mac_addr.octets().map(|e| format!("{e:02X}")).join("-");
        property.set(&mac_text);

        Ok(())
    }
}
