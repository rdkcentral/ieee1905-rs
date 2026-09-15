use crate::cmdu_codec::{LinkMetricRxPair, LinkMetricTxPair};
use crate::rbus::format_media_type;
use crate::rbus::network_al::RBus_Network_Al;
use crate::rbus::network_al_interface::RBus_Network_Al_Interface;
use crate::topology_manager::{Ieee1905InterfaceData, Ieee1905NodeInternal};
use either::Either;
use nom::AsBytes;
use pnet::datalink::MacAddr;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.Network.AL.{i}.Interface.{i}.Link.{i}.
/// - InterfaceId
/// - IEEE1905Id
/// - MediaType
///
pub struct RBus_Network_Al_Interface_Link;

pub struct RBus_Network_Al_Interface_Link_Data<'a> {
    pub neighbour_al_mac: MacAddr,
    pub metric: Either<&'a LinkMetricRxPair, &'a LinkMetricTxPair>,
}

impl RBus_Network_Al_Interface_Link {
    ///////////////////////////////////////////////////////////////////////////
    pub fn iter<'a>(
        node: &'a Ieee1905NodeInternal,
        interface: &Ieee1905InterfaceData,
    ) -> impl Iterator<Item = RBus_Network_Al_Interface_Link_Data<'a>> {
        let rx = node.device_data.link_metric_rx.iter().flat_map(|e| {
            e.interface_pairs.iter().filter_map(|metric| {
                if metric.receiver_interface_mac != interface.mac {
                    return None;
                }
                Some(RBus_Network_Al_Interface_Link_Data {
                    neighbour_al_mac: e.neighbour_al_mac,
                    metric: Either::Left(metric),
                })
            })
        });

        let tx = node.device_data.link_metric_tx.iter().flat_map(|e| {
            e.interface_pairs.iter().filter_map(|metric| {
                if metric.receiver_interface_mac != interface.mac {
                    return None;
                }
                Some(RBus_Network_Al_Interface_Link_Data {
                    neighbour_al_mac: e.neighbour_al_mac,
                    metric: Either::Right(metric),
                })
            })
        });

        rx.chain(tx)
    }

    ///////////////////////////////////////////////////////////////////////////
    pub fn get<'a>(
        node: &'a Ieee1905NodeInternal,
        interface: &Ieee1905InterfaceData,
        table_idx: &[u32],
    ) -> Result<RBus_Network_Al_Interface_Link_Data<'a>, RBusError> {
        let Some(index) = table_idx.get(2).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };
        let Some(metric) = Self::iter(node, interface).nth(index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };
        Ok(metric)
    }
}

impl RBusProviderTableSync for RBus_Network_Al_Interface_Link {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interface = RBus_Network_Al_Interface::get(&node, args.table_idx)?;
        Ok(Self::iter(&node, interface).count() as u32)
    }
}

impl RBusProviderGetter for RBus_Network_Al_Interface_Link {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interface = RBus_Network_Al_Interface::get(&node, args.table_idx)?;
        let link = RBus_Network_Al_Interface_Link::get(&node, interface, args.table_idx)?;

        match args.path_name.as_bytes() {
            b"InterfaceId" => {
                let mac = match link.metric {
                    Either::Left(e) => e.neighbour_interface_mac,
                    Either::Right(e) => e.neighbour_interface_mac,
                };
                args.property.set(&mac.to_string());
                Ok(())
            }
            b"IEEE1905Id" => {
                args.property.set(&link.neighbour_al_mac.to_string());
                Ok(())
            }
            b"MediaType" => {
                let media_type = match link.metric {
                    Either::Left(e) => e.interface_type,
                    Either::Right(e) => e.interface_type,
                };
                args.property.set(format_media_type(media_type));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
