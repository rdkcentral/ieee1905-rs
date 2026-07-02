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
    ) -> Vec<Either<Cow<'a, LinkMetricRxPair>, Cow<'a, LinkMetricTxPair>>> {
        let mut vec = Vec::new();
        let al_mac = neighbor.neighbor.neighbor_al_mac;

        fn to_u16_sat(value: u64) -> u16 {
            u16::try_from(value).unwrap_or(u16::MAX)
        }

        fn to_u32_sat(value: u64) -> u32 {
            u32::try_from(value).unwrap_or(u32::MAX)
        }

        match node {
            RBus_Ieee1905Device_Node::Local(e) => {
                for interface in e.iter() {
                    let neighbors = interface.ieee1905_neighbors.as_deref().unwrap_or_default();
                    let neighbor = neighbors.iter().find(|e| e.neighbor_al_mac == al_mac);
                    let link_stats = interface.link_stats.unwrap_or_default();
                    let phy_rate = to_u16_sat(interface.phy_rate.unwrap_or_default() / 1_000_000);

                    let Some(neighbor) = neighbor else {
                        continue;
                    };

                    vec.push(Either::Left(Cow::Owned(LinkMetricRxPair {
                        receiver_interface_mac: interface.mac,
                        neighbour_interface_mac: neighbor.neighbor_al_mac,
                        interface_type: interface.media_type,
                        packet_errors: to_u32_sat(link_stats.rx_errors),
                        packets_received: to_u32_sat(link_stats.rx_packets),
                        rssi: interface.signal_strength_dbm.unwrap_or(0xffu8 as i8),
                    })));

                    vec.push(Either::Right(Cow::Owned(LinkMetricTxPair {
                        receiver_interface_mac: interface.mac,
                        neighbour_interface_mac: neighbor.neighbor_al_mac,
                        interface_type: interface.media_type,
                        has_more_ieee802_bridges: interface.bridging_flag.into(),
                        packet_errors: to_u32_sat(link_stats.tx_errors),
                        transmitted_packets: to_u32_sat(link_stats.tx_packets),
                        mac_throughput_capacity: phy_rate,
                        link_availability: interface.link_availability.unwrap_or(100).into(),
                        phy_rate,
                    })));
                }
            }
            RBus_Ieee1905Device_Node::Remote(e) => {
                for metric in e.device_data.link_metric_rx.iter() {
                    if metric.neighbour_al_mac == al_mac {
                        vec.extend(
                            metric
                                .interface_pairs
                                .iter()
                                .map(|e| Either::Left(Cow::Borrowed(e))),
                        );
                    }
                }
                for metric in e.device_data.link_metric_tx.iter() {
                    if metric.neighbour_al_mac == al_mac {
                        vec.extend(
                            metric
                                .interface_pairs
                                .iter()
                                .map(|e| Either::Right(Cow::Borrowed(e))),
                        );
                    }
                }
            }
        };
        vec
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

        let metrics = Self::collect(&node, &neighbor);
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

        let metrics = Self::collect(&node, &neighbor);
        let Some(metric) = metrics.get(metric_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"NeighborMACAddress" => {
                let al_mac = neighbor.neighbor.neighbor_al_mac.to_string();
                args.property.set(&al_mac);
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
