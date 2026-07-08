use crate::rbus::network_al::RBus_Network_Al;
use crate::rbus::network_al_interface::RBus_Network_Al_Interface;
use crate::rbus::network_al_interface_link::RBus_Network_Al_Interface_Link;
use either::Either;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.Network.AL.{i}.Interface.{i}.Link.{i}.Metric.
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
pub struct RBus_Network_Al_Interface_Link_Metric;

impl RBusProviderGetter for RBus_Network_Al_Interface_Link_Metric {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interface = RBus_Network_Al_Interface::get(&node, args.table_idx)?;
        let link = RBus_Network_Al_Interface_Link::get(&node, interface, args.table_idx)?;

        match args.path_name.as_bytes() {
            b"IEEE802dot1Bridge" => {
                let has_more_ieee802_bridges = match &link.metric {
                    Either::Left(_) => return Err(RBusError::ElementDoesNotExists),
                    Either::Right(e) => e.has_more_ieee802_bridges != 0,
                };
                args.property.set(&has_more_ieee802_bridges);
                Ok(())
            }
            b"PacketErrors" => {
                match &link.metric {
                    Either::Left(_) => return Err(RBusError::ElementDoesNotExists),
                    Either::Right(e) => args.property.set(&e.packet_errors),
                }
                Ok(())
            }
            b"PacketErrorsReceived" => {
                match &link.metric {
                    Either::Left(e) => args.property.set(&e.packet_errors),
                    Either::Right(_) => return Err(RBusError::ElementDoesNotExists),
                }
                Ok(())
            }
            b"TransmittedPackets" => {
                match &link.metric {
                    Either::Left(_) => return Err(RBusError::ElementDoesNotExists),
                    Either::Right(e) => args.property.set(&e.transmitted_packets),
                }
                Ok(())
            }
            b"PacketsReceived" => {
                match &link.metric {
                    Either::Left(e) => args.property.set(&e.packets_received),
                    Either::Right(_) => return Err(RBusError::ElementDoesNotExists),
                }
                Ok(())
            }
            b"MACThroughputCapacity" => {
                match &link.metric {
                    Either::Left(_) => return Err(RBusError::ElementDoesNotExists),
                    Either::Right(e) => args.property.set(&e.mac_throughput_capacity),
                }
                Ok(())
            }
            b"LinkAvailability" => {
                match &link.metric {
                    Either::Left(_) => return Err(RBusError::ElementDoesNotExists),
                    Either::Right(e) => args.property.set(&e.link_availability),
                }
                Ok(())
            }
            b"PHYRate" => {
                match &link.metric {
                    Either::Left(_) => return Err(RBusError::ElementDoesNotExists),
                    Either::Right(e) => args.property.set(&e.phy_rate),
                }
                Ok(())
            }
            b"RSSI" => {
                match &link.metric {
                    Either::Left(e) => args.property.set(&e.rssi),
                    Either::Right(_) => return Err(RBusError::ElementDoesNotExists),
                }
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
