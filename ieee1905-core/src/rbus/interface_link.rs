use crate::rbus::{format_mac_address, format_media_type, peek_topology_database};
use crate::topology_manager::Ieee1905DeviceData;
use crate::TopologyDatabase;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.Interface.{i}.Link.{i}.
/// - IEEE1905Id
/// - InterfaceId
/// - MediaType
///
pub struct RBus_InterfaceLink;

impl RBus_InterfaceLink {
    pub fn get_links(
        db: &TopologyDatabase,
        table_idx: &[u32],
    ) -> Result<Vec<Ieee1905DeviceData>, RBusError> {
        let Some(if_index) = table_idx.get(0) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let local_interfaces = db.local_interface_list.blocking_read();
        let local_interfaces = local_interfaces.as_deref().unwrap_or_default();
        let Some(local_interface) = local_interfaces.get(*if_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let nodes = db.nodes.blocking_read();
        let nodes = nodes
            .values()
            .filter(|e| e.device_data.local_interface_mac == local_interface.mac)
            .map(|e| e.device_data.clone());

        Ok(nodes.collect())
    }
}

impl RBusProviderTableSync for RBus_InterfaceLink {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let db = peek_topology_database()?;
        let links = Self::get_links(&db, args.table_idx)?;
        Ok(links.len() as u32)
    }
}

impl RBusProviderGetter for RBus_InterfaceLink {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(link_index) = args.table_idx.get(1) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let links = Self::get_links(&db, args.table_idx)?;
        let Some(link) = links.get(*link_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"IEEE1905Id" => {
                args.property.set(&format_mac_address(&link.al_mac));
                Ok(())
            }
            b"InterfaceId" => {
                match link.destination_mac {
                    Some(e) => args.property.set(&format_mac_address(&e)),
                    None => return Err(RBusError::ElementDoesNotExists),
                }
                Ok(())
            }
            b"MediaType" => {
                let interfaces = link.local_interface_list.as_deref().unwrap_or_default();
                match interfaces
                    .iter()
                    .find(|e| e.mac == link.destination_frame_mac)
                {
                    Some(e) => args.property.set(format_media_type(e.media_type)),
                    None => return Err(RBusError::ElementDoesNotExists),
                }
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
