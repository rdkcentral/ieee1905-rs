use crate::cmdu::IEEE1905Neighbor;
use crate::rbus::network_al::RBus_Network_Al;
use crate::rbus::network_al_interface::RBus_Network_Al_Interface;
use crate::rbus::peek_topology_database;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.Network.AL.{i}.Interface.{i}.IEEE1905Neighbor.{i}.
/// - NeighborDeviceId
/// - IEEE1905DeviceRef
/// - IEEE802dot1Bridge
///
pub struct RBus_Network_Al_Interface_Ieee1905Neighbor;

impl RBusProviderTableSync for RBus_Network_Al_Interface_Ieee1905Neighbor {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interface = RBus_Network_Al_Interface::get(&node, args.table_idx)?;
        let neighbors = interface.ieee1905_neighbors.as_deref();
        Ok(neighbors.unwrap_or_default().len() as u32)
    }
}

impl RBusProviderGetter for RBus_Network_Al_Interface_Ieee1905Neighbor {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(index) = args.table_idx.get(2).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interface = RBus_Network_Al_Interface::get(&node, args.table_idx)?;
        let neighbor = interface
            .ieee1905_neighbors
            .as_deref()
            .unwrap_or_default()
            .get(index as usize)
            .ok_or(RBusError::ElementDoesNotExists)?;

        match args.path_name.as_bytes() {
            b"NeighborDeviceId" => {
                args.property.set(&neighbor.neighbor_al_mac.to_string());
                Ok(())
            }
            b"IEEE1905DeviceRef" => {
                let db = peek_topology_database()?;
                let nodes = db.nodes.blocking_read();
                let Some(index) = nodes.get_index_of(&neighbor.neighbor_al_mac) else {
                    return Err(RBusError::ElementDoesNotExists);
                };
                let value = format!("Device.IEEE1905.Network.AL.{index}");
                args.property.set(&value);
                Ok(())
            }
            b"IEEE802dot1Bridge" => {
                let value = (neighbor.neighbor_flags & IEEE1905Neighbor::FLAG_BRIDGED) != 0;
                args.property.set(&value);
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
