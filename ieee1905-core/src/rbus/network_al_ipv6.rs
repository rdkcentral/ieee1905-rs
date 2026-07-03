use crate::cmdu_codec::IPv6AddressType;
use crate::rbus::network_al::RBus_Network_Al;
use crate::topology_manager::Ieee1905NodeInternal;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};
use std::borrow::Cow;
use std::net::Ipv6Addr;

///
/// Device.IEEE1905.Network.AL.{i}.IPv6Address.{i}.
/// - MACAddress
/// - IPv6Address
/// - IPv6AddressType
/// - IPv6AddressOrigin
///
pub struct RBus_Network_Al_IPv6;

impl RBus_Network_Al_IPv6 {
    pub fn count(node: &Ieee1905NodeInternal) -> Result<u32, RBusError> {
        let Some(ipv6) = node.device_data.ipv6.as_ref() else {
            return Ok(0);
        };
        Ok(ipv6
            .entries
            .iter()
            .map(|e| e.routable_addresses.len() as u32 + 1)
            .sum())
    }
}

impl RBusProviderTableSync for RBus_Network_Al_IPv6 {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        Self::count(&RBus_Network_Al::get_node(args.table_idx)?.1)
    }
}

impl RBusProviderGetter for RBus_Network_Al_IPv6 {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(address_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let node = RBus_Network_Al::get_node(args.table_idx)?.1;

        let Some(ipv6) = node.device_data.ipv6.as_ref() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let Some((mac, address, extra)) = ipv6
            .entries
            .iter()
            .flat_map(|e| {
                let link_local = std::iter::once((e.mac_address, e.link_local_address, None));
                let other_addresses = e.routable_addresses.iter().map(|address| {
                    (
                        e.mac_address,
                        address.ipv6_address,
                        Some((address.address_type, address.ipv6_originator)),
                    )
                });
                std::iter::chain(link_local, other_addresses)
            })
            .nth(address_index as usize)
        else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"MACAddress" => {
                args.property.set(&mac.to_string());
                Ok(())
            }
            b"IPv6Address" => {
                args.property.set(&address.to_string());
                Ok(())
            }
            b"IPv6AddressType" => {
                let value = extra.map(|e| match e.0 {
                    IPv6AddressType::Unknown => Cow::Borrowed("Unknown"),
                    IPv6AddressType::DHCP => Cow::Borrowed("DHCP"),
                    IPv6AddressType::Static => Cow::Borrowed("Static"),
                    IPv6AddressType::SLAAC => Cow::Borrowed("SLAAC"),
                    IPv6AddressType::Reserved(e) => format!("Unknown({e})").into(),
                });
                args.property.set(value.as_deref().unwrap_or("LinkLocal"));
                Ok(())
            }
            b"IPv6AddressOrigin" => {
                let value = extra.map_or(Ipv6Addr::UNSPECIFIED, |e| e.1);
                args.property.set(&value.to_string());
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
