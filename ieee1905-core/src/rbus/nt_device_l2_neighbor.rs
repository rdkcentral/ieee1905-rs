use crate::rbus::nt_device::RBus_Ieee1905Device_Node;
use crate::rbus::peek_topology_database;
use either::Either;
use nom::AsBytes;
use pnet::datalink::MacAddr;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.L2Neighbor.{i}.
/// - LocalInterface
/// - NeighborInterfaceId
/// - BehindInterfaceIds
///
pub struct RBus_NetworkTopology_Ieee1905Device_L2Neighbor;

pub struct L2Neighbor<'a> {
    local_if_mac: MacAddr,
    neighbor_if_mac: MacAddr,
    behind_if_macs: &'a [MacAddr],
}

impl RBus_NetworkTopology_Ieee1905Device_L2Neighbor {
    pub fn iter<'a>(node: &'a RBus_Ieee1905Device_Node) -> impl Iterator<Item = L2Neighbor<'a>> {
        match node {
            RBus_Ieee1905Device_Node::Local(e) => Either::Left(e.iter().flat_map(|e| {
                let ieee1905_neighbors =
                    e.ieee1905_neighbors
                        .iter()
                        .flatten()
                        .map(|neighbor| L2Neighbor {
                            local_if_mac: e.mac,
                            neighbor_if_mac: neighbor.neighbor_al_mac,
                            behind_if_macs: &[],
                        });

                let non_ieee1905_neighbors =
                    e.non_ieee1905_neighbors
                        .iter()
                        .flatten()
                        .map(|neighbor| L2Neighbor {
                            local_if_mac: e.mac,
                            neighbor_if_mac: *neighbor,
                            behind_if_macs: &[],
                        });

                ieee1905_neighbors.chain(non_ieee1905_neighbors)
            })),
            RBus_Ieee1905Device_Node::Remote(node) => Either::Right(
                node.device_data
                    .l2_neighbor_devices
                    .iter()
                    .flat_map(|e| e.local_interfaces.iter())
                    .flat_map(|e| {
                        e.neighbors.iter().map(|neighbor| L2Neighbor {
                            local_if_mac: e.mac_address,
                            neighbor_if_mac: neighbor.mac_address,
                            behind_if_macs: &neighbor.behind_mac_addresses,
                        })
                    }),
            ),
        }
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_L2Neighbor {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        let count = Self::iter(&node).count();

        Ok(count as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_L2Neighbor {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(neighbour_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        let mut neighbours = Self::iter(&node);

        let Some(neighbour) = neighbours.nth(neighbour_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"LocalInterface" => {
                args.property.set(&neighbour.local_if_mac.to_string());
                Ok(())
            }
            b"NeighborInterfaceId" => {
                args.property.set(&neighbour.neighbor_if_mac.to_string());
                Ok(())
            }
            b"BehindInterfaceIds" => {
                let macs = Vec::from_iter(neighbour.behind_if_macs.iter().map(|e| e.to_string()));
                args.property.set(&macs.join(","));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
