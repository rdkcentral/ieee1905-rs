use crate::cmdu_codec::MediaTypeSpecialInfoWifi;
use crate::rbus::nt_device::RBus_Ieee1905Device_Node;
use crate::rbus::{format_mac_address, format_media_type, peek_topology_database};
use nom::AsBytes;
use rbus_core::RBusError;
use rbus_provider::element::property::{RBusProviderGetter, RBusProviderGetterArgs};
use rbus_provider::element::table::{RBusProviderTableSync, RBusProviderTableSyncArgs};

///
/// Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.
/// - InterfaceId
/// - MediaType
/// - Role
/// - APChannelBand
/// - FrequencyIndex1
/// - FrequencyIndex2
///
pub struct RBus_NetworkTopology_Ieee1905Device_Interface;

impl RBusProviderTableSync for RBus_NetworkTopology_Ieee1905Device_Interface {
    type UserData = ();

    fn len(&mut self, args: RBusProviderTableSyncArgs<Self::UserData>) -> Result<u32, RBusError> {
        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        Ok(node.local_interfaces().count() as u32)
    }
}

impl RBusProviderGetter for RBus_NetworkTopology_Ieee1905Device_Interface {
    type UserData = ();

    fn get(&mut self, args: RBusProviderGetterArgs<Self::UserData>) -> Result<(), RBusError> {
        let Some(if_index) = args.table_idx.get(1).copied() else {
            return Err(RBusError::ElementDoesNotExists);
        };

        let db = peek_topology_database()?;
        let node = RBus_Ieee1905Device_Node::from(db, args.table_idx)?.1;
        let Some(interface) = node.local_interfaces().nth(if_index as usize) else {
            return Err(RBusError::ElementDoesNotExists);
        };

        match args.path_name.as_bytes() {
            b"InterfaceId" => {
                args.property.set(&format_mac_address(&interface.mac));
                Ok(())
            }
            b"MediaType" => {
                args.property.set(format_media_type(interface.media_type));
                Ok(())
            }
            b"Role" => {
                let wifi_extra = interface.media_type_extra.as_wifi();
                let wifi_extra = wifi_extra.ok_or(RBusError::ElementDoesNotExists)?;

                let value = match wifi_extra.role & MediaTypeSpecialInfoWifi::MASK_ROLE {
                    MediaTypeSpecialInfoWifi::ROLE_802_11AD_PCP_STA => "802.11adPCP",
                    MediaTypeSpecialInfoWifi::ROLE_NON_AP_NON_PCP_STA => "non-AP/non-PCP STA",
                    MediaTypeSpecialInfoWifi::ROLE_AP => "AP",
                    MediaTypeSpecialInfoWifi::ROLE_P2P_CLIENT => "Wi-Fi P2P Client",
                    MediaTypeSpecialInfoWifi::ROLE_P2P_GROUP_OWNER => "Wi-Fi P2P Group Owner",
                    _ => return Err(RBusError::ElementDoesNotExists),
                };

                args.property.set(value);
                Ok(())
            }
            b"APChannelBand" => {
                let extra = interface.media_type_extra.as_wifi();
                let extra = extra.ok_or(RBusError::ElementDoesNotExists)?;

                args.property.set(&extra.ap_channel_band);
                Ok(())
            }
            b"FrequencyIndex1" => {
                let extra = interface.media_type_extra.as_wifi();
                let extra = extra.ok_or(RBusError::ElementDoesNotExists)?;

                args.property.set(&extra.ap_channel_center_frequency_index1);
                Ok(())
            }
            b"FrequencyIndex2" => {
                let extra = interface.media_type_extra.as_wifi();
                let extra = extra.ok_or(RBusError::ElementDoesNotExists)?;

                args.property.set(&extra.ap_channel_center_frequency_index2);
                Ok(())
            }
            _ => Err(RBusError::ElementDoesNotExists),
        }
    }
}
