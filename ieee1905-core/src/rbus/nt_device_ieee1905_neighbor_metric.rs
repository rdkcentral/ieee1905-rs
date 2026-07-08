use crate::cmdu_codec::{LinkMetricRxPair, LinkMetricTxPair};
use crate::rbus::nt_device::RBus_Ieee1905Device_Node;
use crate::rbus::nt_device_ieee1905_neighbor::{
    Ieee1905Neighbor, RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor,
};
use crate::rbus::peek_topology_database;
use either::Either;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};
use std::borrow::Cow;

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.
/// - NeighborMACAddress
/// - IEEE802dot1Bridge
/// - PacketErrors
/// - PacketErrorsReceived
/// - TransmittedPackets
/// - PacketsReceived
/// - MACThroughputCapacity
/// - LinkAvailability
/// - PHYRate
/// - RSSI
///
pub struct RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric;

impl RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric {
    pub fn collect<'a>(
        node: &'a RBus_Ieee1905Device_Node,
        neighbor: &'a Ieee1905Neighbor,
    ) -> Result<Vec<Either<Cow<'a, LinkMetricRxPair>, Cow<'a, LinkMetricTxPair>>>, RBusError> {
        let mut vec = Vec::new();
        let neighbor_al_mac = neighbor.neighbor.neighbor_al_mac;

        match node {
            RBus_Ieee1905Device_Node::Local(e) => {
                let db = peek_topology_database()?;
                let nodes = db.nodes.blocking_read();
                let node = nodes
                    .iter()
                    .find(|e| e.1.device_data.has_port(neighbor_al_mac))
                    .ok_or_else(|| RBusError::ElementDoesNotExists)?;

                for interface in e.iter() {
                    let Some((rx, tx)) = interface.get_link_metric_pair(&node.1.device_data) else {
                        continue;
                    };
                    vec.push(Either::Left(Cow::Owned(rx)));
                    vec.push(Either::Right(Cow::Owned(tx)));
                }
            }
            RBus_Ieee1905Device_Node::Remote(e) => {
                for metric in e.device_data.link_metric_rx.iter() {
                    if metric.neighbour_al_mac != neighbor_al_mac {
                        continue;
                    }
                    for pair in metric.interface_pairs.iter() {
                        vec.push(Either::Left(Cow::Borrowed(pair)));
                    }
                }
                for metric in e.device_data.link_metric_tx.iter() {
                    if metric.neighbour_al_mac != neighbor_al_mac {
                        continue;
                    }
                    for pair in metric.interface_pairs.iter() {
                        vec.push(Either::Right(Cow::Borrowed(pair)));
                    }
                }
            }
        };
        Ok(vec)
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let Some(neighbour_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        let mut neighbors = RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor::iter(&node);

        let Some(neighbor) = neighbors.nth(neighbour_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let metrics = Self::collect(&node, &neighbor)?;
        Ok(metrics.len() as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor_Metric {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(neighbour_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };
        let Some(metric_index) = args.table_idx.get(2).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;

        let mut neighbors = RBus_NetworkTopology_Ieee1905Device_IEEE1905Neighbor::iter(&node);
        let Some(neighbor) = neighbors.nth(neighbour_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let metrics = Self::collect(&node, &neighbor)?;
        let Some(metric) = metrics.get(metric_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"NeighborMACAddress" => {
                let mac = match metric {
                    Either::Left(e) => e.neighbour_interface_mac,
                    Either::Right(e) => e.neighbour_interface_mac,
                };
                args.property.set(&mac.to_string());
                Ok(())
            }
            b"IEEE802dot1Bridge" => match metric {
                Either::Left(_) => Err(RBusError::ElementDoesNotExists),
                Either::Right(e) => {
                    args.property.set(&(e.has_more_ieee802_bridges != 0));
                    Ok(())
                }
            },
            b"PacketErrors" => match metric {
                Either::Left(_) => Err(RBusError::ElementDoesNotExists),
                Either::Right(e) => {
                    args.property.set(&e.packet_errors);
                    Ok(())
                }
            },
            b"PacketErrorsReceived" => match metric {
                Either::Left(e) => {
                    args.property.set(&e.packet_errors);
                    Ok(())
                }
                Either::Right(_) => Err(RBusError::ElementDoesNotExists),
            },
            b"TransmittedPackets" => match metric {
                Either::Left(_) => Err(RBusError::ElementDoesNotExists),
                Either::Right(e) => {
                    args.property.set(&e.transmitted_packets);
                    Ok(())
                }
            },
            b"PacketsReceived" => match metric {
                Either::Left(e) => {
                    args.property.set(&e.packets_received);
                    Ok(())
                }
                Either::Right(_) => Err(RBusError::ElementDoesNotExists),
            },
            b"MACThroughputCapacity" => match metric {
                Either::Left(_) => Err(RBusError::ElementDoesNotExists),
                Either::Right(e) => {
                    args.property.set(&e.mac_throughput_capacity);
                    Ok(())
                }
            },
            b"LinkAvailability" => match metric {
                Either::Left(_) => Err(RBusError::ElementDoesNotExists),
                Either::Right(e) => {
                    args.property.set(&e.link_availability);
                    Ok(())
                }
            },
            b"PHYRate" => match metric {
                Either::Left(_) => Err(RBusError::ElementDoesNotExists),
                Either::Right(e) => {
                    args.property.set(&e.phy_rate);
                    Ok(())
                }
            },
            b"RSSI" => match metric {
                Either::Left(e) => {
                    args.property.set(&e.rssi);
                    Ok(())
                }
                Either::Right(_) => Err(RBusError::ElementDoesNotExists),
            },
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
