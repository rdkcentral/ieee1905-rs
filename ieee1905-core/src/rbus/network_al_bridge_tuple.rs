use crate::rbus::network_al::RBus_Network_Al;
use crate::topology_manager::Ieee1905NodeInternal;
use indexmap::IndexMap;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.Network.AL.{i}.BridgingTuple.{i}.
/// - InterfaceList
///
pub struct RBus_Network_Al_BridgingTuple;

impl RBus_Network_Al_BridgingTuple {
    pub fn collect(node: &Ieee1905NodeInternal) -> IndexMap<u32, Vec<usize>> {
        let interfaces = node.device_data.local_interface_list.as_deref();

        let mut map = IndexMap::new();
        for (index, interface) in interfaces.unwrap_or_default().iter().enumerate() {
            let Some(tuple) = interface.bridging_tuple else {
                continue;
            };
            map.entry(tuple).or_insert_with(Vec::new).push(index);
        }
        map
    }
}

impl RBusProviderTableSync for RBus_Network_Al_BridgingTuple {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let tuples = Self::collect(&node);
        Ok(tuples.len() as u32)
    }
}

impl RBusProviderGetter for RBus_Network_Al_BridgingTuple {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(tuple_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let (node_index, node) = RBus_Network_Al::get_node(args.table_idx)?;
        let tuples = Self::collect(&node);

        let Some(tuple) = tuples.get_index(tuple_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"InterfaceList" => {
                let iter = tuple.1.iter();
                let interfaces =
                    Vec::from_iter(iter.map(|e| {
                        format!("Device.IEEE1905.Network.0.AL.{node_index}.Interface.{e}")
                    }));
                args.property.set(&interfaces.join(","));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
