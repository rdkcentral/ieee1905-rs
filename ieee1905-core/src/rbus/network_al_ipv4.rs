use crate::cmdu_codec::IPv4AddressType;
use crate::rbus::network_al::RBus_Network_Al;
use crate::topology_manager::Ieee1905NodeInternal;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};
use std::borrow::Cow;

///
/// Device.IEEE1905.Network.AL.{i}.IPv4Address.{i}.
/// - MACAddress
/// - IPv4Address
/// - IPv4AddressType
/// - DHCPServer
///
pub struct RBus_Network_Al_IPv4;

impl RBus_Network_Al_IPv4 {
    pub fn count(node: &Ieee1905NodeInternal) -> Result<u32, RBusError> {
        let Some(ipv4) = node.device_data.ipv4.as_ref() else {
            return Ok(0);
        };
        Ok(ipv4.entries.iter().map(|e| e.addresses.len() as u32).sum())
    }
}

impl RBusProviderTableSync for RBus_Network_Al_IPv4 {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        Self::count(&RBus_Network_Al::get_node(args.table_idx)?.1)
    }
}

impl RBusProviderGetter for RBus_Network_Al_IPv4 {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(address_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let node = RBus_Network_Al::get_node(args.table_idx)?.1;

        let Some(ipv4) = node.device_data.ipv4.as_ref() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let Some((mac, address)) = ipv4
            .entries
            .iter()
            .flat_map(|e| e.addresses.iter().map(|address| (e.mac, address)))
            .nth(address_index as usize)
        else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"MACAddress" => {
                args.property.set(&mac.to_string());
                Ok(())
            }
            b"IPv4Address" => {
                args.property.set(&address.address.to_string());
                Ok(())
            }
            b"IPv4AddressType" => {
                let value = match address.kind {
                    IPv4AddressType::Unknown => Cow::Borrowed("Unknown"),
                    IPv4AddressType::DHCP => Cow::Borrowed("DHCP"),
                    IPv4AddressType::Static => Cow::Borrowed("Static"),
                    IPv4AddressType::AutoIP => Cow::Borrowed("Auto-IP"),
                    IPv4AddressType::Reserved(e) => format!("Unknown({e})").into(),
                };
                args.property.set(&*value);
                Ok(())
            }
            b"DHCPServer" => {
                args.property.set(&address.dhcp_server.to_string());
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
