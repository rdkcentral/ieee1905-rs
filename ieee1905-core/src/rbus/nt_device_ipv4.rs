use crate::cmdu_codec::{IPv4AddressType, Ipv4Address};
use crate::rbus::nt_device::RBus_Ieee1905Device_Node;
use crate::rbus::peek_topology_database;
use nom::AsBytes;
use pnet::datalink::MacAddr;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.
/// - MACAddress
/// - IPv4Address
/// - IPv4AddressType
/// - DHCPServer
///
pub struct RBus_NetworkTopology_Ieee1905Device_IPv4;

impl RBus_NetworkTopology_Ieee1905Device_IPv4 {
    pub fn iter<'a>(
        node: &'a RBus_Ieee1905Device_Node,
    ) -> impl Iterator<Item = (MacAddr, &'a Ipv4Address)> {
        node.ipv4_addresses()
            .into_iter()
            .flat_map(|e| e.entries.iter())
            .flat_map(|e| {
                let mac = e.mac;
                e.addresses.iter().map(move |address| (mac, address))
            })
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_IPv4 {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        Ok(Self::iter(&node).count() as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_IPv4 {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(address_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        let Some((mac, ipv4)) = Self::iter(&node).nth(address_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"MACAddress" => {
                args.property.set(&mac.to_string());
                Ok(())
            }
            b"IPv4Address" => {
                args.property.set(&ipv4.address.to_string());
                Ok(())
            }
            b"IPv4AddressType" => {
                let value = match ipv4.kind {
                    IPv4AddressType::DHCP => "DHCP",
                    IPv4AddressType::Static => "Static",
                    IPv4AddressType::AutoIP => "Auto-IP",
                    _ => "Unknown",
                };
                args.property.set(value);
                Ok(())
            }
            b"DHCPServer" => {
                args.property.set(&ipv4.dhcp_server.to_string());
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
