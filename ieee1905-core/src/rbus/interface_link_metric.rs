use crate::rbus::interface_link::RBus_InterfaceLink;
use crate::rbus::peek_topology_database;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};

///
/// Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric
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
pub struct RBus_InterfaceLinkMetric;

impl RBusProviderGetter for RBus_InterfaceLinkMetric {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(link_index) = args.table_idx.get(1) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let (interface, links) = RBus_InterfaceLink::get_links(&db, args.table_idx)?;
        let Some(_) = links.get(*link_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let stats = interface.link_stats.unwrap_or_default();
        match args.path_name.as_bytes() {
            b"IEEE802dot1Bridge" => {
                args.property.set(&interface.bridging_flag);
                Ok(())
            }
            b"PacketErrors" => {
                args.property.set(&stats.tx_errors);
                Ok(())
            }
            b"PacketErrorsReceived" => {
                args.property.set(&stats.rx_errors);
                Ok(())
            }
            b"TransmittedPackets" => {
                args.property.set(&stats.tx_packets);
                Ok(())
            }
            b"PacketsReceived" => {
                args.property.set(&stats.rx_packets);
                Ok(())
            }
            b"MACThroughputCapacity" => {
                let value = interface.phy_rate.unwrap_or_default() / 1_000_000;
                args.property.set(&value);
                Ok(())
            }
            b"LinkAvailability" => {
                let value = interface.link_availability.unwrap_or(100);
                args.property.set(&value);
                Ok(())
            }
            b"PHYRate" => {
                let value = interface.phy_rate.unwrap_or_default() / 1_000_000;
                args.property.set(&value);
                Ok(())
            }
            b"RSSI" => {
                let value = interface.signal_strength_dbm;
                args.property.set(&value.unwrap_or(i8::MIN).unsigned_abs());
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
