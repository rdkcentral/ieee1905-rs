use crate::cmdu::L2Neighbor;
use crate::rbus::network_al::RBus_Network_Al;
use crate::rbus::network_al_interface::RBus_Network_Al_Interface;
use crate::topology_manager::{Ieee1905InterfaceData, Ieee1905NodeInternal};
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.Network.AL.{i}.Interface.{i}.L2Neighbor.{i}.
/// - NeighborInterfaceId
/// - BehindInterfaceIds
///
pub struct RBus_Network_Al_Interface_L2Neighbor;

impl RBus_Network_Al_Interface_L2Neighbor {
    pub fn iter<'a>(
        node: &'a Ieee1905NodeInternal,
        interface: &Ieee1905InterfaceData,
    ) -> impl Iterator<Item = &'a L2Neighbor> {
        node.device_data
            .l2_neighbor_devices
            .iter()
            .flat_map(|e| e.local_interfaces.iter())
            .filter(|e| interface.mac == e.mac_address)
            .flat_map(|e| e.neighbors.iter())
    }
}

impl RBusProviderTableSync for RBus_Network_Al_Interface_L2Neighbor {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interface = RBus_Network_Al_Interface::get(&node, args.table_idx)?;
        let neighbors = RBus_Network_Al_Interface_L2Neighbor::iter(&node, interface);
        Ok(neighbors.count() as u32)
    }
}

impl RBusProviderGetter for RBus_Network_Al_Interface_L2Neighbor {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(index) = args.table_idx.get(2).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interface = RBus_Network_Al_Interface::get(&node, args.table_idx)?;
        let neighbor = RBus_Network_Al_Interface_L2Neighbor::iter(&node, interface)
            .nth(index as usize)
            .ok_or(RBusError::ElementDoesNotExists)?;

        match args.path_name.as_bytes() {
            b"NeighborInterfaceId" => {
                args.property.set(&neighbor.mac_address.to_string());
                Ok(())
            }
            b"BehindInterfaceIds" => {
                let macs = neighbor.behind_mac_addresses.iter();
                let macs = macs.map(|e| e.to_string()).collect::<Vec<_>>();
                args.property.set(&macs.join(","));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
