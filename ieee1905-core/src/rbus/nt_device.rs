use crate::rbus::nt_device_bridge::RBus_NetworkTopology_Ieee1905Device_BridgingTuple;
use crate::rbus::nt_device_non_ieee1905_neighbor::RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor;
use crate::rbus::{format_mac_address, peek_topology_database};
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.
/// - IEEE1905Id
/// - BridgingTupleNumberOfEntries
///
pub struct RBus_NetworkTopology_Ieee1905Device;

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let _ = args;
        Ok(peek_topology_database()?.nodes.blocking_read().len() as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let lock = peek_topology_database()?.nodes.blocking_read();

        let Some(node_index) = args.table_idx.get(0).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };
        let Some((node_al_mac, node)) = lock.get_index(node_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"IEEE1905Id" => {
                args.property.set(&format_mac_address(&node_al_mac));
                Ok(())
            }
            b"BridgingTupleNumberOfEntries" => {
                let tuples =
                    RBus_NetworkTopology_Ieee1905Device_BridgingTuple::get_tuples_from_node(&node)?;
                args.property.set(&(tuples.len() as u32));
                Ok(())
            }
            b"NonIEEE1905NeighborNumberOfEntries" => {
                let neighbors =
                    RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor::iter_neighbors(node);
                args.property.set(&(neighbors.count() as u32));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
