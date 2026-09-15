use crate::cmdu_codec::MediaTypeSpecialInfoWifi;
use crate::rbus::format_media_type;
use crate::rbus::network_al::RBus_Network_Al;
use crate::rbus::network_al_interface_l2_neighbor::RBus_Network_Al_Interface_L2Neighbor;
use crate::rbus::network_al_interface_link::RBus_Network_Al_Interface_Link;
use crate::topology_manager::{Ieee1905InterfaceData, Ieee1905NodeInternal};
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.Network.AL.{i}.Interface.{i}.
/// - InterfaceId
/// - MediaType
/// - PowerState
/// - NetworkMembership
/// - Role
/// - APChannelBand
/// - FrequencyIndex1
/// - FrequencyIndex2
/// - LinkNumberOfEntries
/// - IEEE1905NeighborNumberOfEntries
/// - NonIEEE1905NeighborNumberOfEntries
/// - L2NeighborNumberOfEntries
///
pub struct RBus_Network_Al_Interface;

impl RBus_Network_Al_Interface {
    pub fn get<'a>(
        node: &'a Ieee1905NodeInternal,
        table_idx: &[u32],
    ) -> Result<&'a Ieee1905InterfaceData, RBusError> {
        let Some(index) = table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let interfaces = node.device_data.local_interface_list.as_deref();
        let interfaces = interfaces.unwrap_or_default();

        let Some(interface) = interfaces.get(index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };
        Ok(interface)
    }
}

impl RBusProviderTableSync for RBus_Network_Al_Interface {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interfaces = node.device_data.local_interface_list.as_deref();
        Ok(interfaces.unwrap_or_default().len() as u32)
    }
}

impl RBusProviderGetter for RBus_Network_Al_Interface {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let node = RBus_Network_Al::get_node(args.table_idx)?.1;
        let interface = RBus_Network_Al_Interface::get(&node, args.table_idx)?;

        match args.path_name.as_bytes() {
            b"InterfaceId" => {
                args.property.set(&interface.mac.to_string());
                Ok(())
            }
            b"MediaType" => {
                args.property.set(format_media_type(interface.media_type));
                Ok(())
            }
            b"PowerState" => {
                args.property.set("On");
                Ok(())
            }
            b"NetworkMembership" => {
                let wifi = interface.media_type_extra.as_wifi();
                let value = wifi.map(|e| e.bssid.to_string());
                args.property.set(&value.unwrap_or_default());
                Ok(())
            }
            b"Role" => {
                let wifi = interface.media_type_extra.as_wifi();
                let value = wifi.map(|e| match e.role {
                    MediaTypeSpecialInfoWifi::ROLE_AP => "AP",
                    MediaTypeSpecialInfoWifi::ROLE_NO_AD_NO_PCP_STATION => "non-AP/non-PCP STA",
                    MediaTypeSpecialInfoWifi::ROLE_P2P_CLIENT => "Wi-Fi P2P Client",
                    MediaTypeSpecialInfoWifi::ROLE_P2P_GROUP_OWNER => "Wi-Fi P2P Group Owner",
                    MediaTypeSpecialInfoWifi::ROLE_802_11AD_PCP => "802.11adPCP",
                    _ => "",
                });
                args.property.set(value.unwrap_or_default());
                Ok(())
            }
            b"APChannelBand" => {
                let wifi = interface.media_type_extra.as_wifi();
                let value = wifi.map_or(0, |e| e.ap_channel_band);
                args.property.set(&value);
                Ok(())
            }
            b"FrequencyIndex1" => {
                let wifi = interface.media_type_extra.as_wifi();
                let value = wifi.map_or(0, |e| e.ap_channel_center_frequency_index1);
                args.property.set(&value);
                Ok(())
            }
            b"FrequencyIndex2" => {
                let wifi = interface.media_type_extra.as_wifi();
                let value = wifi.map_or(0, |e| e.ap_channel_center_frequency_index2);
                args.property.set(&value);
                Ok(())
            }
            b"LinkNumberOfEntries" => {
                let iter = RBus_Network_Al_Interface_Link::iter(&node, interface);
                args.property.set(&(iter.count() as u32));
                Ok(())
            }
            b"IEEE1905NeighborNumberOfEntries" => {
                let neighbors = interface.ieee1905_neighbors.as_deref();
                let value = neighbors.unwrap_or_default().len() as u32;
                args.property.set(&value);
                Ok(())
            }
            b"NonIEEE1905NeighborNumberOfEntries" => {
                let neighbors = interface.non_ieee1905_neighbors.as_deref();
                let value = neighbors.unwrap_or_default().len() as u32;
                args.property.set(&value);
                Ok(())
            }
            b"L2NeighborNumberOfEntries" => {
                let iter = RBus_Network_Al_Interface_L2Neighbor::iter(&node, interface);
                args.property.set(&(iter.count() as u32));
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
