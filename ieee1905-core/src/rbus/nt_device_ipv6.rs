use crate::cmdu_codec::IPv6AddressType;
use crate::rbus::nt_device::RBus_Ieee1905Device_Node;
use crate::rbus::peek_topology_database;
use nom::AsBytes;
use pnet::datalink::MacAddr;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};
use std::net::Ipv6Addr;

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.
/// - MACAddress
/// - IPv6Address
/// - IPv6AddressType
/// - IPv6AddressOrigin
///
pub struct RBus_NetworkTopology_Ieee1905Device_IPv6;

pub struct IPv6Info<'a> {
    mac: MacAddr,
    address: &'a Ipv6Addr,
    extra: Option<(IPv6AddressType, &'a Ipv6Addr)>,
}

impl RBus_NetworkTopology_Ieee1905Device_IPv6 {
    pub fn get_ipv6_pairs<'a>(
        node: &'a RBus_Ieee1905Device_Node,
    ) -> impl Iterator<Item = IPv6Info<'a>> {
        node.ipv6_addresses()
            .into_iter()
            .flat_map(|e| e.entries.iter())
            .flat_map(|e| {
                let info = IPv6Info {
                    mac: e.mac_address,
                    address: &e.link_local_address,
                    extra: None,
                };
                std::iter::once(info).chain(e.other_addresses.iter().map(|address| IPv6Info {
                    mac: e.mac_address,
                    address: &address.ipv6_address,
                    extra: Some((address.address_type, &address.ipv6_originator)),
                }))
            })
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_IPv6 {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        Ok(Self::get_ipv6_pairs(&node).count() as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_IPv6 {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(if_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        let Some(info) = Self::get_ipv6_pairs(&node).nth(if_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"MACAddress" => {
                args.property.set(&info.mac.to_string());
                Ok(())
            }
            b"IPv6Address" => {
                args.property.set(&info.address.to_string());
                Ok(())
            }
            b"IPv6AddressType" => {
                let value = match info.extra.map(|e| e.0) {
                    Some(IPv6AddressType::DHCP) => "DHCP",
                    Some(IPv6AddressType::Static) => "Static",
                    Some(IPv6AddressType::SLAAC) => "SLAAC",
                    None => "LinkLocal",
                    _ => "Unknown",
                };
                args.property.set(value);
                Ok(())
            }
            b"IPv6AddressOrigin" => {
                let value = info.extra.map_or(Ipv6Addr::UNSPECIFIED, |e| *e.1);
                args.property.set(&value.to_string());
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
