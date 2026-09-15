use crate::cmdu_codec::{Ieee1905ProfileVersion, SupportedFreqBand};
use crate::rbus::network_al_bridge_tuple::RBus_Network_Al_BridgingTuple;
use crate::rbus::network_al_ipv4::RBus_Network_Al_IPv4;
use crate::rbus::network_al_ipv6::RBus_Network_Al_IPv6;
use crate::rbus::peek_topology_database;
use crate::topology_manager::Ieee1905NodeInternal;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};
use std::borrow::Cow;
use tokio::sync::RwLockReadGuard;

///
/// Device.IEEE1905.Network.AL.{i}.
/// - IEEE1905Id
/// - Version
/// - RegistrarFreqBand
/// - FriendlyName
/// - ManufacturerName
/// - ManufacturerModel
/// - ControlURL
/// - IPv4AddressNumberOfEntries
/// - IPv6AddressNumberOfEntries
/// - InterfaceNumberOfEntries
/// - BridgingTupleNumberOfEntries
///
pub struct RBus_Network_Al;

impl RBus_Network_Al {
    pub fn get_node(
        table_idx: &[u32],
    ) -> Result<(u32, RwLockReadGuard<'_, Ieee1905NodeInternal>), RBusError> {
        let Some(node_index) = table_idx.get(0).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let nodes = db.nodes.blocking_read();

        match RwLockReadGuard::try_map(nodes, |e| Some(e.get_index(node_index as usize)?.1)) {
            Ok(e) => Ok((node_index, e)),
            Err(_) => Err(RBusError::ElementDoesNotExists),
        }
    }
}

impl RBusProviderTableSync for RBus_Network_Al {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let _ = args;
        let db = peek_topology_database()?;
        let len = db.nodes.blocking_read().len();
        Ok(len as u32)
    }
}

impl RBusProviderGetter for RBus_Network_Al {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let node = Self::get_node(args.table_idx)?.1;

        match args.path_name.as_bytes() {
            b"IEEE1905Id" => {
                args.property.set(&node.device_data.al_mac.to_string());
                Ok(())
            }
            b"Version" => {
                let value = match node.device_data.ieee1905_profile_version {
                    Ieee1905ProfileVersion::Ieee1905_1 => Cow::Borrowed("1905.1"),
                    Ieee1905ProfileVersion::Ieee1905_1a => Cow::Borrowed("1905.1a"),
                    Ieee1905ProfileVersion::Reserved(e) => format!("unknown({e})").into(),
                };
                args.property.set(&*value);
                Ok(())
            }
            b"RegistrarFreqBand" => {
                let value = node.device_data.supported_freq_band.map(|e| match e {
                    SupportedFreqBand::Band_802_11_2_4 => Cow::Borrowed("802.11 2.4 GHz"),
                    SupportedFreqBand::Band_802_11_5 => Cow::Borrowed("802.11 5 GHz"),
                    SupportedFreqBand::Band_802_11_60 => Cow::Borrowed("802.11 60 GHz"),
                    SupportedFreqBand::Reserved(e) => format!("unknown({e})").into(),
                });
                args.property.set(&*value.unwrap_or_default());
                Ok(())
            }
            b"FriendlyName" => {
                let info = node.device_data.device_identification_type.as_ref();
                let value = info.map(|e| e.friendly_name.as_str());
                args.property.set(value.unwrap_or_default());
                Ok(())
            }
            b"ManufacturerName" => {
                let info = node.device_data.device_identification_type.as_ref();
                let value = info.map(|e| e.manufacturer_name.as_str());
                args.property.set(value.unwrap_or_default());
                Ok(())
            }
            b"ManufacturerModel" => {
                let info = node.device_data.device_identification_type.as_ref();
                let value = info.map(|e| e.manufacturer_model.as_str());
                args.property.set(value.unwrap_or_default());
                Ok(())
            }
            b"ControlURL" => {
                let control_url = node.device_data.control_url.as_ref();
                let value = control_url.map(|e| e.url.as_str());
                args.property.set(value.unwrap_or_default());
                Ok(())
            }
            b"IPv4AddressNumberOfEntries" => {
                let value = RBus_Network_Al_IPv4::count(&node)?;
                args.property.set(&value);
                Ok(())
            }
            b"IPv6AddressNumberOfEntries" => {
                let value = RBus_Network_Al_IPv6::count(&node)?;
                args.property.set(&value);
                Ok(())
            }
            b"InterfaceNumberOfEntries" => {
                let interfaces = node.device_data.local_interface_list.as_deref();
                let value = interfaces.unwrap_or_default().len();
                args.property.set(&(value as u32));
                Ok(())
            }
            b"BridgingTupleNumberOfEntries" => {
                let tuples = RBus_Network_Al_BridgingTuple::collect(&node);
                args.property.set(&(tuples.len() as u32));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
