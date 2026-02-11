use crate::cmdu_codec::{DeviceIdentificationType, Ieee1905ProfileVersion, SupportedFreqBand};
use crate::rbus::nt_device_bridge::RBus_NetworkTopology_Ieee1905Device_BridgingTuple;
use crate::rbus::nt_device_non_ieee1905_neighbor::RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor;
use crate::rbus::{format_mac_address, peek_topology_database};
use crate::topology_manager::{Ieee1905InterfaceData, Ieee1905LocalInterface, Ieee1905Node};
use crate::TopologyDatabase;
use either::Either;
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};
use std::borrow::Cow;
use tokio::sync::RwLockReadGuard;

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.
/// - IEEE1905Id
/// - Version
/// - RegistrarFreqBand
/// - FriendlyName
/// - ManufacturerName
/// - ManufacturerModel
/// - BridgingTupleNumberOfEntries
/// - NonIEEE1905NeighborNumberOfEntries
///
pub struct RBus_NetworkTopology_Ieee1905Device;

impl RBus_NetworkTopology_Ieee1905Device {
    pub fn count_rows(db: &TopologyDatabase) -> usize {
        // 1st items is always ourselves
        db.nodes.blocking_read().len() + 1
    }
}

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let _ = args;
        let db = peek_topology_database()?;
        Ok(Self::count_rows(&db) as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(&db, args.table_idx)?.1;

        match args.path_name.as_bytes() {
            b"IEEE1905Id" => {
                let al_mac_str = match node {
                    RBus_Ieee1905Device_Node::Local(_) => {
                        let mac = format_mac_address(&db.local_mac.blocking_read());
                        format!("{mac}-local",)
                    }
                    RBus_Ieee1905Device_Node::Remote(e) => {
                        format_mac_address(&e.device_data.al_mac)
                    }
                };
                args.property.set(&al_mac_str);
                Ok(())
            }
            b"Version" => {
                let value = match node.ieee1905profile_version().unwrap_or_default() {
                    Ieee1905ProfileVersion::Ieee1905_1 => Cow::Borrowed("1905.1"),
                    Ieee1905ProfileVersion::Ieee1905_1a => Cow::Borrowed("1905.1a"),
                    Ieee1905ProfileVersion::Reserved(e) => format!("unknown({e})").into(),
                };
                args.property.set(value.as_ref());
                Ok(())
            }
            b"RegistrarFreqBand" => {
                let value = match node.supported_freq_band() {
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
                let value = match node.device_identification_type() {
                    None => "unknown",
                    Some(e) => &e.friendly_name,
                };
                args.property.set(value);
                Ok(())
            }
            b"ManufacturerName" => {
                let value = match node.device_identification_type() {
                    None => "unknown",
                    Some(e) => &e.manufacturer_name,
                };
                args.property.set(value);
                Ok(())
            }
            b"ManufacturerModel" => {
                let value = match node.device_identification_type() {
                    None => "unknown",
                    Some(e) => &e.manufacturer_model,
                };
                args.property.set(value);
                Ok(())
            }
            b"BridgingTupleNumberOfEntries" => {
                let tuples = RBus_NetworkTopology_Ieee1905Device_BridgingTuple::get_tuples(&node);
                args.property.set(&(tuples.len() as u32));
                Ok(())
            }
            b"NonIEEE1905NeighborNumberOfEntries" => {
                let neighbors =
                    RBus_NetworkTopology_Ieee1905Device_NonIEEE1905Neighbor::iter_neighbors(&node);
                args.property.set(&(neighbors.count() as u32));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}

///
/// Helper struct to unify local and remote info
///
pub enum RBus_Ieee1905Device_Node<'a> {
    Local(RwLockReadGuard<'a, [Ieee1905LocalInterface]>),
    Remote(RwLockReadGuard<'a, Ieee1905Node>),
}

impl<'a> RBus_Ieee1905Device_Node<'a> {
    pub fn from(db: &'a TopologyDatabase, table_idx: &[u32]) -> Result<(u32, Self), RBusError> {
        let Some(node_index) = table_idx.get(0).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let Some(index) = node_index.checked_sub(1) else {
            let ifs = db.local_interface_list.blocking_read();
            let ifs = RwLockReadGuard::map(ifs, |e| e.as_deref().unwrap_or_default());
            return Ok((node_index, Self::Local(ifs)));
        };

        let nodes = db.nodes.blocking_read();
        match RwLockReadGuard::try_map(nodes, |e| Some(e.get_index(index as usize)?.1)) {
            Ok(e) => Ok((node_index, Self::Remote(e))),
            Err(_) => Err(RBusError::ElementDoesNotExists),
        }
    }

    pub fn ieee1905profile_version(&self) -> Option<Ieee1905ProfileVersion> {
        match self {
            RBus_Ieee1905Device_Node::Local(_) => Some(Ieee1905ProfileVersion::Ieee1905_1),
            RBus_Ieee1905Device_Node::Remote(e) => e.device_data.ieee1905profile_version,
        }
    }

    pub fn supported_freq_band(&self) -> Option<SupportedFreqBand> {
        match self {
            RBus_Ieee1905Device_Node::Local(_) => None,
            RBus_Ieee1905Device_Node::Remote(e) => e.device_data.supported_freq_band,
        }
    }

    pub fn device_identification_type(&self) -> Option<&DeviceIdentificationType> {
        match self {
            RBus_Ieee1905Device_Node::Local(_) => None,
            RBus_Ieee1905Device_Node::Remote(e) => {
                e.device_data.device_identification_type.as_ref()
            }
        }
    }

    pub fn local_interfaces(&'a self) -> impl Iterator<Item = &'a Ieee1905InterfaceData> {
        match self {
            RBus_Ieee1905Device_Node::Local(e) => Either::Left(e.iter().map(|e| &**e)),
            RBus_Ieee1905Device_Node::Remote(e) => {
                let ifs = e.device_data.local_interface_list.as_deref();
                Either::Right(ifs.unwrap_or_default().iter())
            }
        }
    }
}
