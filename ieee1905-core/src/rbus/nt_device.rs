use crate::cmdu_codec::{Ieee1905ProfileVersion, SupportedFreqBand};
use crate::rbus::nt_device_bridge::RBus_NetworkTopology_Ieee1905Device_BridgingTuple;
use crate::rbus::{format_mac_address, peek_topology_database};
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};
use std::borrow::Cow;

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
            b"Version" => {
                let value = match node.device_data.ieee1905profile_version.unwrap_or_default() {
                    Ieee1905ProfileVersion::Ieee1905_1 => Cow::Borrowed("1905.1"),
                    Ieee1905ProfileVersion::Ieee1905_1a => Cow::Borrowed("1905.1a"),
                    Ieee1905ProfileVersion::Reserved(e) => format!("unknown({e})").into(),
                };
                args.property.set(value.as_ref());
                Ok(())
            }
            b"RegistrarFreqBand" => {
                let value = match node.device_data.supported_freq_band {
                    Some(SupportedFreqBand::Band_802_11_2_4) => Cow::Borrowed("802.11 2.4 GHz"),
                    Some(SupportedFreqBand::Band_802_11_5) => Cow::Borrowed("802.11 5 GHz"),
                    Some(SupportedFreqBand::Band_802_11_60) => Cow::Borrowed("802.11 60 GHz"),
                    Some(SupportedFreqBand::Reserved(e)) => format!("unknown({e})").into(),
                    None => Cow::Borrowed("unknown"),
                };
                args.property.set(value.as_ref());
                Ok(())
            }
            b"FriendlyName" => {
                let value = match &node.device_data.device_identification_type {
                    None => "unknown",
                    Some(e) => &e.friendly_name,
                };
                args.property.set(value);
                Ok(())
            }
            b"ManufacturerName" => {
                let value = match &node.device_data.device_identification_type {
                    None => "unknown",
                    Some(e) => &e.manufacturer_name,
                };
                args.property.set(value);
                Ok(())
            }
            b"ManufacturerModel" => {
                let value = match &node.device_data.device_identification_type {
                    None => "unknown",
                    Some(e) => &e.manufacturer_model,
                };
                args.property.set(value);
                Ok(())
            }
            b"BridgingTupleNumberOfEntries" => {
                let tuples =
                    RBus_NetworkTopology_Ieee1905Device_BridgingTuple::get_tuples_from_node(&node)?;
                args.property.set(&(tuples.len() as u32));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
