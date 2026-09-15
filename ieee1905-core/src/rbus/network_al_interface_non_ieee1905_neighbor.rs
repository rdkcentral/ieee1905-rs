use crate::rbus::network_al::RBus_Network_Al;
use crate::rbus::network_al_interface::RBus_Network_Al_Interface;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.Network.AL.{i}.Interface.{i}.NonIEEE1905Neighbor.{i}.
/// - NeighborInterfaceId
///
pub struct RBus_Network_Al_Interface_NonIeee1905Neighbor;

impl RBusProviderTableSync for RBus_Network_Al_Interface_NonIeee1905Neighbor {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interface = RBus_Network_Al_Interface::get(&node, args.table_idx)?;
        let neighbors = interface.non_ieee1905_neighbors.as_deref();
        Ok(neighbors.unwrap_or_default().len() as u32)
    }
}

impl RBusProviderGetter for RBus_Network_Al_Interface_NonIeee1905Neighbor {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(index) = args.table_idx.get(2).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interface = RBus_Network_Al_Interface::get(&node, args.table_idx)?;
        let neighbor = interface
            .non_ieee1905_neighbors
            .as_deref()
            .unwrap_or_default()
            .get(index as usize)
            .ok_or(RBusError::ElementDoesNotExists)?;

        match args.path_name.as_bytes() {
            b"NeighborInterfaceId" => {
                args.property.set(&neighbor.to_string());
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
