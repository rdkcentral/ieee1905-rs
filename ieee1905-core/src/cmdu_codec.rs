/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#![deny(warnings)]
// External crates
use nom::Err as NomErr;
use nom::{
    bytes::complete::take,
    error::{Error, ErrorKind},
    number::complete::{be_u16, be_u8},
    IResult,
};

use pnet::datalink::MacAddr;
use std::fmt::Debug;

// Internal modules
use crate::cmdu_reassembler::CmduReassemblyError;
use crate::tlv_cmdu_codec::TLV;

///////////////////////////////////////////////////////////////////////////
//DEFINITION OF CMDU TYPES and IEEE1905 TLVs
///////////////////////////////////////////////////////////////////////////

pub const IEEE1905_CONTROL_ADDRESS: MacAddr = MacAddr(0x01, 0x80, 0xC2, 0x00, 0x00, 0x13);

#[derive(Debug, PartialEq, Eq)]
pub enum CMDUType {
    TopologyDiscovery,
    TopologyNotification,
    TopologyQuery,
    TopologyResponse,
    LinkMetricQuery,
    LinkMetricResponse,
    ApAutoConfigSearch,
    ApAutoConfigResponse,
    Unknown(u16), // To handle unknown or unsupported CMDU types
}

impl CMDUType {
    // Convert from u16 to CMDUType enum variant
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0000 => CMDUType::TopologyDiscovery,
            0x0001 => CMDUType::TopologyNotification,
            0x0002 => CMDUType::TopologyQuery,
            0x0003 => CMDUType::TopologyResponse,
            0x0005 => CMDUType::LinkMetricQuery,
            0x0006 => CMDUType::LinkMetricResponse,
            0x0007 => CMDUType::ApAutoConfigSearch,
            0x0008 => CMDUType::ApAutoConfigResponse,

            _ => CMDUType::Unknown(value), // For unrecognized CMDU types
        }
    }

    // Convert from CMDUType enum variant to u16
    pub fn to_u16(&self) -> u16 {
        match *self {
            CMDUType::TopologyDiscovery => 0x0000,
            CMDUType::TopologyNotification => 0x0001,
            CMDUType::TopologyQuery => 0x0002,
            CMDUType::TopologyResponse => 0x0003,
            CMDUType::LinkMetricQuery => 0x0005,
            CMDUType::LinkMetricResponse => 0x0006,
            //TODO remove this linkMetric
            CMDUType::ApAutoConfigSearch => 0x0007,
            CMDUType::ApAutoConfigResponse => 0x0008,
            CMDUType::Unknown(value) => value, // Return the unknown value as-is
        }
    }
}
///////////////////////////////////////////////////////////////////////////
//DEFINITION OF MESSAGE VERSION
///////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageVersion {
    Version2013 = 0x00,
    Version2014 = 0x01,
    Version2020 = 0x02,
    Version2025 = 0x03,
}

impl MessageVersion {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(MessageVersion::Version2013),
            0x01 => Some(MessageVersion::Version2014),
            0x02 => Some(MessageVersion::Version2020),
            0x03 => Some(MessageVersion::Version2025),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

///////////////////////////////////////////////////////////////////////////
//Comcast selector
///////////////////////////////////////////////////////////////////////////
pub const COMCAST_OUI: [u8; 3] = [0x00, 0x90, 0x96];
pub const COMCAST_QUERY_TAG: &[u8] = &[0x00, 0x01, 0x00];
///////////////////////////////////////////////////////////////////////////
//DEFINITION OF IEEE1905 TLV TYPES
///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub enum IEEE1905TLVType {
    EndOfMessage,
    AlMacAddress,
    MacAddress,
    DeviceInformation,
    DeviceBridgingCapability,
    NonIeee1905NeighborDevices,
    Ieee1905NeighborDevices,
    VendorSpecificInfo,
    SearchedRole,
    SupportedRole,
    Unknown(u8), // To handle unknown or unsupported TLV types
}

impl IEEE1905TLVType {
    // Convert a u8 into the appropriate TLVType enum variant
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => IEEE1905TLVType::EndOfMessage,
            0x01 => IEEE1905TLVType::AlMacAddress,
            0x02 => IEEE1905TLVType::MacAddress,
            0x03 => IEEE1905TLVType::DeviceInformation,
            0x04 => IEEE1905TLVType::DeviceBridgingCapability,
            0x06 => IEEE1905TLVType::NonIeee1905NeighborDevices,
            0x07 => IEEE1905TLVType::Ieee1905NeighborDevices,
            0x0b => IEEE1905TLVType::VendorSpecificInfo,
            0x0d => IEEE1905TLVType::SearchedRole,
            0x0f => IEEE1905TLVType::SupportedRole,
            _ => IEEE1905TLVType::Unknown(value), // For unrecognized types
        }
    }

    // Convert a TLVType enum variant back into the corresponding u8 value
    pub fn to_u8(&self) -> u8 {
        match *self {
            IEEE1905TLVType::EndOfMessage => 0x00,
            IEEE1905TLVType::AlMacAddress => 0x01,
            IEEE1905TLVType::MacAddress => 0x02,
            IEEE1905TLVType::DeviceInformation => 0x03,
            IEEE1905TLVType::DeviceBridgingCapability => 0x04,
            IEEE1905TLVType::NonIeee1905NeighborDevices => 0x06,
            IEEE1905TLVType::Ieee1905NeighborDevices => 0x07,
            IEEE1905TLVType::VendorSpecificInfo => 0x0b,
            IEEE1905TLVType::SearchedRole => 0x0d,
            IEEE1905TLVType::SupportedRole => 0x0f,
            IEEE1905TLVType::Unknown(value) => value, // Return the unknown value as-is
        }
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct AlMacAddress {
    pub al_mac_address: MacAddr,
}

impl AlMacAddress {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, mac_bytes) = take(6usize)(input)?;

        let al_mac_address = MacAddr::new(
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        );

        Ok((input, Self { al_mac_address }))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[
            self.al_mac_address.0,
            self.al_mac_address.1,
            self.al_mac_address.2,
            self.al_mac_address.3,
            self.al_mac_address.4,
            self.al_mac_address.5,
        ]);
        bytes
    }
}
///////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq)]
pub struct MacAddress {
    pub mac_address: MacAddr,
}

impl MacAddress {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, mac_bytes) = take(6usize)(input)?;

        let mac_address = MacAddr::new(
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        );

        Ok((input, Self { mac_address }))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[
            self.mac_address.0,
            self.mac_address.1,
            self.mac_address.2,
            self.mac_address.3,
            self.mac_address.4,
            self.mac_address.5,
        ]);
        bytes
    }
}
///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LocalInterface {
    pub mac_address: MacAddr,
    pub media_type: u16,
    pub special_info: Vec<u8>, // Special info field
}

impl LocalInterface {
    pub fn new(mac_address: MacAddr, media_type: u16, special_info: Vec<u8>) -> Self {
        Self {
            mac_address,
            media_type,
            special_info,
        }
    }

    /// Serializes the `LocalInterface` into a byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize MAC address (6 bytes)
        bytes.extend_from_slice(&[
            self.mac_address.0,
            self.mac_address.1,
            self.mac_address.2,
            self.mac_address.3,
            self.mac_address.4,
            self.mac_address.5,
        ]);

        // Serialize media type (2 bytes)
        bytes.extend_from_slice(&self.media_type.to_be_bytes());

        // Serialize special_info: first byte is the length, followed by the content
        bytes.push(self.special_info.len() as u8);
        bytes.extend_from_slice(&self.special_info);

        bytes
    }

    /// Parses a `LocalInterface` from a byte slice.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < 8 {
            return Err(NomErr::Failure(nom::error::Error::new(
                input,
                ErrorKind::Eof,
            )));
        }

        // Parse MAC address (6 bytes)
        let mac_address = MacAddr::new(input[0], input[1], input[2], input[3], input[4], input[5]);

        // Parse media type (2 bytes)
        let media_type = u16::from_be_bytes([input[6], input[7]]);

        // Parse special_info
        let (input, special_info_length) = be_u8(&input[8..])?;
        let (input, special_info) = take(special_info_length as usize)(input)?;

        Ok((
            input,
            LocalInterface {
                mac_address,
                media_type,
                special_info: special_info.to_vec(),
            },
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DeviceInformation {
    pub al_mac_address: MacAddr,                   // Added AlMacAddress
    pub local_interface_count: u8,                 // Number of local interfaces
    pub local_interface_list: Vec<LocalInterface>, // List of local interfaces
}

impl DeviceInformation {
    pub fn new(al_mac_address: MacAddr, local_interface_list: Vec<LocalInterface>) -> Self {
        Self {
            al_mac_address,
            local_interface_count: local_interface_list.len() as u8,
            local_interface_list,
        }
    }

    /// Serializes the `DeviceInformation` TLV to raw bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize AlMacAddress (6 bytes)
        bytes.extend_from_slice(&[
            self.al_mac_address.0,
            self.al_mac_address.1,
            self.al_mac_address.2,
            self.al_mac_address.3,
            self.al_mac_address.4,
            self.al_mac_address.5,
        ]);

        // Serialize local_interface_count (1 byte)
        bytes.push(self.local_interface_count);

        // Serialize each LocalInterface
        for local_interface in &self.local_interface_list {
            bytes.extend_from_slice(&local_interface.serialize());
        }

        bytes
    }

    /// Parses a `DeviceInformation` TLV from raw bytes.
    pub fn parse(input: &[u8], input_length: u16) -> IResult<&[u8], Self> {
        // Parse AlMacAddress (6 bytes)
        let (input, al_mac_bytes) = take(6usize)(input)?;
        let al_mac_address = MacAddr::new(
            al_mac_bytes[0],
            al_mac_bytes[1],
            al_mac_bytes[2],
            al_mac_bytes[3],
            al_mac_bytes[4],
            al_mac_bytes[5],
        );

        // Parse local_interface_count (1 byte)
        let (input, local_interface_count) = be_u8(input)?;

        // Parse each LocalInterface
        let mut local_interface_list = Vec::new();
        let mut remaining_input = input;
        for _ in 0..local_interface_count {
            let (new_input, local_interface) = LocalInterface::parse(remaining_input)?;
            local_interface_list.push(local_interface);
            remaining_input = new_input;
        }

        // Ensure the parsed length matches the TLV length
        let expected_length = 6
            + 1
            + local_interface_list
                .iter()
                .map(|li| 8 + 1 + li.special_info.len())
                .sum::<usize>() as u16;
        if expected_length != input_length {
            return Err(NomErr::Failure(nom::error::Error::new(
                remaining_input,
                ErrorKind::LengthValue,
            )));
        }

        Ok((
            remaining_input,
            DeviceInformation {
                al_mac_address,
                local_interface_count,
                local_interface_list,
            },
        ))
    }
}

///////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq)]
pub struct BridgingTuple {
    pub bridging_mac_count: u8,
    pub bridging_mac_list: Vec<MacAddr>,
}

impl BridgingTuple {
    /// Parses a `BridgingTuple` from a byte slice
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        // Parse the bridging_mac_count (1 byte)
        let (mut input, bridging_mac_count) = be_u8(input)?;

        let mut bridging_mac_list = Vec::new();

        // Parse each MAC address (6 bytes per MAC)
        for _ in 0..bridging_mac_count {
            if input.len() < 6 {
                return Err(NomErr::Failure(Error::new(input, ErrorKind::Eof)));
            }

            let mac_address =
                MacAddr::new(input[0], input[1], input[2], input[3], input[4], input[5]);
            bridging_mac_list.push(mac_address);

            // Advance input
            input = &input[6..];
        }

        Ok((
            input,
            BridgingTuple {
                bridging_mac_count,
                bridging_mac_list,
            },
        ))
    }

    /// Serializes the `BridgingTuple` into a byte vector
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the bridging_mac_count (u8)
        bytes.push(self.bridging_mac_count);

        // Serialize each MAC address (6 bytes per MAC)
        for mac_address in &self.bridging_mac_list {
            bytes.extend_from_slice(&[
                mac_address.0,
                mac_address.1,
                mac_address.2,
                mac_address.3,
                mac_address.4,
                mac_address.5,
            ]);
        }

        bytes
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DeviceBridgingCapability {
    pub bridging_tuples_count: u8,
    pub bridging_tuples_list: Vec<BridgingTuple>,
}

impl DeviceBridgingCapability {
    /// Parses a `DeviceBridgingCapability` from a byte slice
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        // Parse the bridging_tuples_count (1 byte)
        let (mut input, bridging_tuples_count) = be_u8(input)?;

        let mut bridging_tuples_list = Vec::new();

        // Parse each BridgingTuple
        for _ in 0..bridging_tuples_count {
            let (next_input, bridging_tuple) = BridgingTuple::parse(input)?;
            bridging_tuples_list.push(bridging_tuple);
            input = next_input;
        }

        Ok((
            input,
            DeviceBridgingCapability {
                bridging_tuples_count,
                bridging_tuples_list,
            },
        ))
    }

    /// Serializes the `DeviceBridgingCapability` into a byte vector
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the bridging_tuples_count (u8)
        bytes.push(self.bridging_tuples_count);

        // Serialize each BridgingTuple
        for bridging_tuple in &self.bridging_tuples_list {
            bytes.extend_from_slice(&bridging_tuple.serialize());
        }

        bytes
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NonIEEE1905Neighbor {
    pub neighbor_mac: MacAddr,
}
impl NonIEEE1905Neighbor {
    // Parse function for NonIEEE1905Neighbor
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, mac_bytes) = take(6usize)(input)?;

        let neighbor_mac = MacAddr::new(
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        );

        Ok((input, NonIEEE1905Neighbor { neighbor_mac }))
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the MAC address (6 bytes)
        bytes.extend_from_slice(&[
            self.neighbor_mac.0,
            self.neighbor_mac.1,
            self.neighbor_mac.2,
            self.neighbor_mac.3,
            self.neighbor_mac.4,
            self.neighbor_mac.5,
        ]);

        bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NonIEEE1905LocalInterfaceNeighborhood {
    pub local_mac_address: MacAddr,
    pub neighbor_list: Vec<NonIEEE1905Neighbor>,
}

impl NonIEEE1905LocalInterfaceNeighborhood {
    pub fn parse(input: &[u8], neighbor_count: u8) -> IResult<&[u8], Self> {
        // Parse the local MAC address (6 bytes)
        let (input, local_mac_bytes) = take(6usize)(input)?;
        let local_mac_address = MacAddr::new(
            local_mac_bytes[0],
            local_mac_bytes[1],
            local_mac_bytes[2],
            local_mac_bytes[3],
            local_mac_bytes[4],
            local_mac_bytes[5],
        );

        // Parse the list of neighbors
        let mut neighbor_list = Vec::new();
        let mut remaining_input = input;

        for _ in 0..neighbor_count {
            let (next_input, neighbor) = NonIEEE1905Neighbor::parse(remaining_input)?;
            neighbor_list.push(neighbor);
            remaining_input = next_input;
        }

        Ok((
            remaining_input,
            NonIEEE1905LocalInterfaceNeighborhood {
                local_mac_address,
                neighbor_list,
            },
        ))
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the local MAC address (6 bytes)
        bytes.extend_from_slice(&[
            self.local_mac_address.0,
            self.local_mac_address.1,
            self.local_mac_address.2,
            self.local_mac_address.3,
            self.local_mac_address.4,
            self.local_mac_address.5,
        ]);

        // Serialize each neighbor
        for neighbor in &self.neighbor_list {
            bytes.extend_from_slice(&neighbor.serialize());
        }

        bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NonIeee1905NeighborDevices {
    pub local_mac_address: MacAddr,      // Single local MAC address
    pub neighborhood_list: Vec<MacAddr>, // List of neighbor MACs
}

impl NonIeee1905NeighborDevices {
    /// **Parsing function**
    pub fn parse(input: &[u8], neighbor_count: u16) -> IResult<&[u8], Self> {
        let mut remaining_input = input;

        // **Step 1: Ensure There Are Enough Bytes for the Local MAC Address**
        if remaining_input.len() < 6 {
            return Err(nom::Err::Error(nom::error::Error::new(
                remaining_input,
                nom::error::ErrorKind::Eof,
            )));
        }

        // **Parse Local MAC Address**
        let (next_input, mac_bytes) = take(6usize)(remaining_input)?;
        let local_mac_address = MacAddr::new(
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        );
        remaining_input = next_input;

        // **Step 2: Ensure There Are Enough Bytes for All Neighbor MAC Addresses**
        let required_bytes = (neighbor_count as usize) * 6;
        if remaining_input.len() < required_bytes {
            return Err(nom::Err::Error(nom::error::Error::new(
                remaining_input,
                nom::error::ErrorKind::Eof,
            )));
        }

        // **Parse Neighbors**
        let mut neighborhood_list = Vec::new();
        for _ in 0..neighbor_count {
            let (next_input, mac_bytes) = take(6usize)(remaining_input)?;
            let neighbor_mac_address = MacAddr::new(
                mac_bytes[0],
                mac_bytes[1],
                mac_bytes[2],
                mac_bytes[3],
                mac_bytes[4],
                mac_bytes[5],
            );
            neighborhood_list.push(neighbor_mac_address);
            remaining_input = next_input;
        }

        Ok((
            remaining_input, // Return remaining input
            NonIeee1905NeighborDevices {
                local_mac_address,
                neighborhood_list,
            },
        ))
    }

    /// **Serialization function**
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // **Step 1: Serialize the Local MAC Address (6 bytes)**
        bytes.extend_from_slice(&[
            self.local_mac_address.0,
            self.local_mac_address.1,
            self.local_mac_address.2,
            self.local_mac_address.3,
            self.local_mac_address.4,
            self.local_mac_address.5,
        ]);

        // **Step 2: Serialize each Neighbor MAC Address (6 bytes each)**
        for neighbor in &self.neighborhood_list {
            bytes.extend_from_slice(&[
                neighbor.0, neighbor.1, neighbor.2, neighbor.3, neighbor.4, neighbor.5,
            ]);
        }

        bytes
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IEEE1905Neighbor {
    pub neighbor_al_mac: MacAddr, // Renamed field
    pub neighbor_flags: u8,
}

impl IEEE1905Neighbor {
    /// Parse an `IEEE1905Neighbor` from a byte slice
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        // Parse the neighbor_al_mac (6 bytes)
        let (input, mac_bytes) = take(6usize)(input)?;
        let neighbor_al_mac = MacAddr::new(
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        );

        // Parse the neighbor_flags (1 byte)
        let (input, neighbor_flags) = be_u8(input)?;

        // Return the parsed IEEE1905Neighbor struct
        Ok((
            input,
            IEEE1905Neighbor {
                neighbor_al_mac, // Updated field name
                neighbor_flags,
            },
        ))
    }

    /// Serialize the `IEEE1905Neighbor` into a byte vector
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the neighbor_al_mac (6 bytes)
        bytes.extend_from_slice(&[
            self.neighbor_al_mac.0,
            self.neighbor_al_mac.1,
            self.neighbor_al_mac.2,
            self.neighbor_al_mac.3,
            self.neighbor_al_mac.4,
            self.neighbor_al_mac.5,
        ]);

        // Serialize the neighbor_flags (1 byte)
        bytes.push(self.neighbor_flags);

        bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ieee1905NeighborDevice {
    pub local_mac_address: MacAddr,
    pub neighborhood_list: Vec<IEEE1905Neighbor>,
}

impl Ieee1905NeighborDevice {
    /// Parse an `Ieee1905NeighborDevice` from a byte slice
    pub fn parse(input: &[u8], neighbor_count: usize) -> IResult<&[u8], Self> {
        // Parse the local_mac_address (6 bytes)
        let (input, mac_bytes) = take(6usize)(input)?;
        let local_mac_address = MacAddr::new(
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        );

        // Parse the list of IEEE1905Neighbor objects
        let mut neighborhood_list = Vec::new();
        let mut remaining_input = input;

        for _ in 0..neighbor_count {
            let (next_input, neighbor) = IEEE1905Neighbor::parse(remaining_input)?;
            neighborhood_list.push(neighbor);
            remaining_input = next_input;
        }

        Ok((
            remaining_input,
            Ieee1905NeighborDevice {
                local_mac_address,
                neighborhood_list,
            },
        ))
    }

    /// Serialize the `Ieee1905NeighborDevice` into a byte vector
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the local_mac_address (6 bytes)
        bytes.extend_from_slice(&[
            self.local_mac_address.0,
            self.local_mac_address.1,
            self.local_mac_address.2,
            self.local_mac_address.3,
            self.local_mac_address.4,
            self.local_mac_address.5,
        ]);

        // Serialize each IEEE1905Neighbor in the neighborhood_list
        for neighbor in &self.neighborhood_list {
            bytes.extend_from_slice(&neighbor.serialize());
        }

        bytes
    }
}

///////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq)]
pub struct VendorSpecificInfo {
    pub oui: [u8; 3],
    pub vendor_data: Vec<u8>,
}
impl VendorSpecificInfo {
    // Function to parse VendorSpecificTLV from a RawTLV
    pub fn parse(input: &[u8], input_length: u16) -> IResult<&[u8], Self> {
        let (input, oui) = take(3usize)(input)?;
        let (input, vendor_data) = take(input_length as usize - 3)(input)?;
        Ok((
            input,
            Self {
                oui: [oui[0], oui[1], oui[2]],
                vendor_data: vendor_data.to_vec(),
            },
        ))
    }
    // Serialize the VendorSpecificValue into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.oui); // Add OUI
        bytes.extend_from_slice(&self.vendor_data); // Add vendor-specific data
        bytes
    }
}
///////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq)]
pub struct SearchedRole {
    pub role: u8,
}

impl SearchedRole {
    /// Parse `SearchedRole` from raw TLV data
    pub fn parse(input: &[u8], _input_length: u16) -> IResult<&[u8], Self> {
        let (input, role_bytes) = take(1usize)(input)?;
        let role = role_bytes[0];

        if role != 0x00 {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify)));
        }

        Ok((
            input,
            Self {
                role: role_bytes[0],
            },
        ))
    }

    /// Serialize `SearchedRole` into bytes
    pub fn serialize(&self) -> Vec<u8> {
        vec![self.role]
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct SupportedRole {
    pub role: u8,
}

impl SupportedRole {
    /// Parse `SupportedRole` from raw TLV data, ensuring the role is exactly 0x00
    pub fn parse(input: &[u8], _input_length: u16) -> IResult<&[u8], Self> {
        let (input, role_bytes) = take(1usize)(input)?;
        let role = role_bytes[0];

        if role != 0x00 {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify)));
        }

        Ok((input, Self { role }))
    }

    /// Serialize `SupportedRole` into bytes
    pub fn serialize(&self) -> Vec<u8> {
        vec![self.role]
    }
}
///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CMDU {
    pub message_version: u8,
    pub reserved: u8,
    pub message_type: u16,
    pub message_id: u16,
    pub fragment: u8,
    pub flags: u8,
    pub payload: Vec<u8>,
}
impl CMDU {
    pub fn get_tlvs(&self) -> anyhow::Result<Vec<TLV>> {
        let mut tlvs: Vec<TLV> = vec![];
        let mut remaining_input = self.payload.as_slice();
        let mut has_reached_end = false;
        while !remaining_input.is_empty() && !has_reached_end {
            match TLV::parse(remaining_input) {
                Ok(tlv) => {
                    tracing::trace!("Parsed TLV {:?}", tlv.1);
                    // The minimum Ethernet frame length (over the wire) is 60 bytes
                    // For very small frames like Topology Discovery, it is likely
                    // there will be zero padding after the content of the frame
                    if tlv.1.tlv_type == IEEE1905TLVType::EndOfMessage.to_u8()
                        && tlv.1.tlv_length == 0
                        && tlv.1.tlv_value.is_none()
                    {
                        has_reached_end = true;
                    }
                    tlvs.push(tlv.1);
                    remaining_input = tlv.0;
                }
                Err(e) => {
                    tracing::error!("Failed to parse TLV {:?}", e);

                    let hex_string = remaining_input
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<String>>()
                        .join(" ");
                    tracing::trace!("Remaining {}", hex_string);

                    return Err(anyhow::anyhow!("Failed to parse TLV: {e}"));
                }
            }
        }
        Ok(tlvs)
    }
    //Force message version to be used for CMDUs received via HLE SDUs
    pub fn set_message_version(&mut self, version: MessageVersion) {
        self.message_version = version.to_u8();
    }

    pub fn get_message_version(self) -> Option<MessageVersion> {
        MessageVersion::from_u8(self.message_version)
    }

    // Parse the CMDU from a byte slice
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, message_version) = be_u8(input)?;
        let (input, reserved) = be_u8(input)?;
        let (input, message_type) = be_u16(input)?;
        let (input, message_id) = be_u16(input)?;
        let (input, fragment) = be_u8(input)?;
        let (input, flags) = be_u8(input)?;

        tracing::trace!("CMDU_parse: message_version {message_version:?}, reserved {reserved:?},
                         message_type: {message_type:?}, message_id {message_id:?}, fragment: {fragment:?}");
        // Since in size based fragmentation remaining input might have incomplete TLV's
        // there is one case in which it can be checked in here.
        // when fragment is equal to zero.

        let cmdu = CMDU {
            message_version,
            reserved,
            message_type,
            message_id,
            fragment,
            flags,
            payload: input.into(),
        };
        if flags & 0x80 != 0 && fragment == 0 {
            let Ok(tlvs) = cmdu.get_tlvs() else {
                return Err(NomErr::Failure(Error::new(input, ErrorKind::Tag)));
            };
            // We can check if TLV's can be parsed and last TLV is really EoF
            if let Some(last_tlv) = tlvs.last() {
                if last_tlv.tlv_type != IEEE1905TLVType::EndOfMessage.to_u8()
                    || last_tlv.tlv_length != 0
                    || last_tlv.tlv_value.is_some()
                {
                    tracing::error!("TLV: Last is not end of message");
                    return Err(NomErr::Failure(Error::new(input, ErrorKind::Tag)));
                }
            };
        }
        tracing::trace!("Returning CMDU. Might have incomplete TLV's due to size fragmentation");
        Ok((&[], cmdu))
    }

    // Convert the CMDU to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the CMDU fields
        bytes.push(self.message_version); // 1 byte: message_version
        bytes.push(self.reserved); // 1 byte: reserved
        bytes.extend_from_slice(&self.message_type.to_be_bytes()); // 2 bytes: message_type (u16)
        bytes.extend_from_slice(&self.message_id.to_be_bytes()); // 2 bytes: message_id (u16)
        bytes.push(self.fragment); // 1 byte: fragment
        bytes.push(self.flags); // 1 byte: flags

        // Serialize payload u8 vec
        bytes.extend_from_slice(self.payload.as_slice());

        bytes
    }

    pub fn fragment(mut self, max_size: usize) -> Vec<CMDU> {
        let tlvs_size = self.payload.len(); // tlv_size is just payload size
        let total_size = 8 + tlvs_size;

        if total_size <= max_size {
            self.fragment = 0;
            self.flags |= 0x80; // EndOfMessage
            return vec![self];
        }

        let mut fragments = Vec::new();

        let mut fragment_no = 0;
        while !self.payload.is_empty() {
            let end = 1492.min(self.payload.len());
            let max_bytes = self.payload.drain(0..end).collect();

            let current_fragment = CMDU {
                message_version: self.message_version,
                reserved: self.reserved,
                message_type: self.message_type,
                message_id: self.message_id,
                fragment: fragment_no,
                flags: self.flags & !0x80,
                payload: max_bytes,
            };
            fragments.push(current_fragment);
            fragment_no += 1;
        }
        if let Some(last_elem) = fragments.last_mut() {
            last_elem.flags |= 0x80;
        }
        fragments
    }

    pub fn reassemble(fragments: Vec<CMDU>) -> Result<CMDU, CmduReassemblyError> {
        if fragments.is_empty() {
            return Err(CmduReassemblyError::EmptyFragments);
        }

        // Check metadata consistency
        let message_version = fragments[0].message_version;
        let message_type = fragments[0].message_type;
        let message_id = fragments[0].message_id;

        if !fragments.iter().all(|f| {
            f.message_version == message_version
                && f.message_type == message_type
                && f.message_id == message_id
        }) {
            return Err(CmduReassemblyError::InconsistentMetadata);
        }

        // Sort by fragment number
        let mut fragments = fragments;
        fragments.sort_by_key(|f| f.fragment);

        // Check that fragment indices are continuous
        for (i, frag) in fragments.iter().enumerate() {
            if frag.fragment != i as u8 {
                return Err(CmduReassemblyError::MissingFragments);
            }
        }

        // Verify LastFragment flag on the last fragment
        if fragments.last().is_none_or(|e| e.flags & 0x80 == 0) {
            return Err(CmduReassemblyError::MissingLastFragment);
        }

        // Reassemble payload
        let mut full_payload = Vec::new();
        for frag in fragments {
            full_payload.extend(frag.payload);
        }

        Ok(CMDU {
            message_version,
            reserved: 0,
            message_type,
            message_id,
            fragment: 0,
            flags: 0x80, // Set EndOfMessage on the reassembled CMDU
            payload: full_payload,
        })
    }
    /// Returns true if the CMDU has the `EndOfMessage` flag set (0x80)
    pub fn is_last_fragment(&self) -> bool {
        self.flags & 0x80 != 0
    }

    /// Returns true if this CMDU is part of a fragmented set
    pub fn is_fragmented(&self) -> bool {
        self.fragment > 0 || !self.is_last_fragment()
    }
    /// Calculates the total size of the CMDU (header + all TLVs)
    pub fn total_size(&self) -> usize {
        let header_size = 8; // message_version (1) + reserved (1) + message_type (2) + message_id (2) + fragment (1) + flags (1)
        let payload_size = self.payload.len();
        header_size + payload_size
    }
}
#[cfg(test)]
pub mod tests {
    use super::*;

    // A helper function for creating some dummy TLV with provided payload
    fn make_dummy_tlv(index: u8, size: usize) -> TLV {
        let value = vec![index; size];
        TLV {
            tlv_type: index,
            tlv_length: size as u16,
            tlv_value: Some(value),
        }
    }

    pub fn make_dummy_cmdu(tlv_sizes: Vec<usize>) -> CMDU {
        let payload: Vec<TLV> = tlv_sizes
            .into_iter()
            .enumerate()
            .map(|(i, size)| make_dummy_tlv(i as u8, size))
            .collect();

        let mut serialized_payload: Vec<u8> = vec![];
        for tlv in payload {
            serialized_payload.extend(tlv.serialize());
        }

        CMDU {
            message_version: 0x01,
            reserved: 0x00,
            message_type: 0x0001,
            message_id: 0x1234,
            fragment: 0,
            flags: 0x00,
            payload: serialized_payload,
        }
    }

    // Verify the correctness of working to_u8 and from_u8 functions from MessageVersion enum
    #[test]
    fn test_message_version_check_version_correctness() {
        // Expect successes
        assert_eq!(
            MessageVersion::Version2013.to_u8(),
            MessageVersion::from_u8(0).unwrap().to_u8()
        );
        assert_eq!(
            MessageVersion::Version2014.to_u8(),
            MessageVersion::from_u8(1).unwrap().to_u8()
        );
        assert_eq!(
            MessageVersion::Version2020.to_u8(),
            MessageVersion::from_u8(2).unwrap().to_u8()
        );
        assert_eq!(
            MessageVersion::Version2025.to_u8(),
            MessageVersion::from_u8(3).unwrap().to_u8()
        );
        assert_eq!(None, MessageVersion::from_u8(4));
    }

    // Verify the correctness of conversion from u16 to CMDUType enum
    #[test]
    fn test_cmdu_type_check_from_u16() {
        // Expect successes
        assert_eq!(CMDUType::from_u16(0), CMDUType::TopologyDiscovery);
        assert_eq!(CMDUType::from_u16(1), CMDUType::TopologyNotification);
        assert_eq!(CMDUType::from_u16(2), CMDUType::TopologyQuery);
        assert_eq!(CMDUType::from_u16(3), CMDUType::TopologyResponse);
        assert_eq!(CMDUType::from_u16(4), CMDUType::Unknown(4));
        assert_eq!(CMDUType::from_u16(5), CMDUType::LinkMetricQuery);
        assert_eq!(CMDUType::from_u16(6), CMDUType::LinkMetricResponse);
        assert_eq!(CMDUType::from_u16(7), CMDUType::ApAutoConfigSearch);
        assert_eq!(CMDUType::from_u16(8), CMDUType::ApAutoConfigResponse);
    }

    // Verify function for getting message version of CMDU
    #[test]
    fn test_cmdu_type_get_message_version() {
        // Create a dummy CMDU with message_version field set to 0x1
        let cmdu = make_dummy_cmdu(vec![100]);

        // Expect success getting message version of CMDU
        assert_eq!(cmdu.get_message_version(), MessageVersion::from_u8(1));
    }

    // Verify the correctness of conversion to u16 from CMDUType
    #[test]
    fn test_cmdu_type_check_to_u16() {
        // Expect successes
        assert_eq!(CMDUType::TopologyDiscovery.to_u16(), 0);
        assert_eq!(CMDUType::TopologyNotification.to_u16(), 1);
        assert_eq!(CMDUType::TopologyQuery.to_u16(), 2);
        assert_eq!(CMDUType::TopologyResponse.to_u16(), 3);
        assert_eq!(CMDUType::Unknown(4).to_u16(), 4);
        assert_eq!(CMDUType::LinkMetricQuery.to_u16(), 5);
        assert_eq!(CMDUType::LinkMetricResponse.to_u16(), 6);
        assert_eq!(CMDUType::ApAutoConfigSearch.to_u16(), 7);
        assert_eq!(CMDUType::ApAutoConfigResponse.to_u16(), 8);
    }

    // Verify the correctness of conversion from u8 to IEEE1905TLVType
    #[test]
    fn test_ieee1905_tlv_type_check_from_u8() {
        // Expect successes
        assert_eq!(
            IEEE1905TLVType::from_u8(0x00),
            IEEE1905TLVType::EndOfMessage
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x01),
            IEEE1905TLVType::AlMacAddress
        );
        assert_eq!(IEEE1905TLVType::from_u8(0x02), IEEE1905TLVType::MacAddress);
        assert_eq!(
            IEEE1905TLVType::from_u8(0x03),
            IEEE1905TLVType::DeviceInformation
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x04),
            IEEE1905TLVType::DeviceBridgingCapability
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x05),
            IEEE1905TLVType::Unknown(0x05)
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x06),
            IEEE1905TLVType::NonIeee1905NeighborDevices
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x07),
            IEEE1905TLVType::Ieee1905NeighborDevices
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x0b),
            IEEE1905TLVType::VendorSpecificInfo
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x0d),
            IEEE1905TLVType::SearchedRole
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x0f),
            IEEE1905TLVType::SupportedRole
        );
    }

    // Verify the correctness of conversion from IEEE1905TLVType enum to u8
    #[test]
    fn test_ieee1905_tlv_type_check_to_u8() {
        // Expect successes
        assert_eq!(IEEE1905TLVType::EndOfMessage.to_u8(), 0x00);
        assert_eq!(IEEE1905TLVType::AlMacAddress.to_u8(), 0x01);
        assert_eq!(IEEE1905TLVType::MacAddress.to_u8(), 0x02);
        assert_eq!(IEEE1905TLVType::DeviceInformation.to_u8(), 0x03);
        assert_eq!(IEEE1905TLVType::DeviceBridgingCapability.to_u8(), 0x04);
        assert_eq!(IEEE1905TLVType::Unknown(0x05).to_u8(), 0x05);
        assert_eq!(IEEE1905TLVType::NonIeee1905NeighborDevices.to_u8(), 0x06);
        assert_eq!(IEEE1905TLVType::Ieee1905NeighborDevices.to_u8(), 0x07);
        assert_eq!(IEEE1905TLVType::VendorSpecificInfo.to_u8(), 0x0b);
        assert_eq!(IEEE1905TLVType::SearchedRole.to_u8(), 0x0d);
        assert_eq!(IEEE1905TLVType::SupportedRole.to_u8(), 0x0f);
    }

    // Verify changing version by using set_message_version function
    #[test]
    fn test_message_version_change() {
        let mut cmd = CMDU {
            message_version: MessageVersion::Version2013.to_u8(),
            reserved: 0,
            message_type: 0x0001,
            message_id: 42,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload: vec![],
        };

        assert_eq!(cmd.message_version, 0x00);

        // Change message version to Version2020
        cmd.set_message_version(MessageVersion::Version2020);

        // Expect success in changing message version to Version2020
        assert_eq!(cmd.message_version, 0x02);
    }

    // Verify the correctness of calculation of total_size field
    #[test]
    fn test_total_size() {
        // Small CMDU with TLVs that fits in one fragment
        let cmdu = make_dummy_cmdu(vec![100, 200, 300]); // 600 bytes

        assert_eq!(cmdu.total_size(), cmdu.serialize().len());
    }

    // Verify CMDU fragmentation and reassembly
    #[test]
    fn test_fragmentation_and_reassembly() {
        // TLVs that will force at least 2 fragments
        let cmdu = make_dummy_cmdu(vec![600, 600, 400]); // ~1600 bytes total

        // Fragment CMDU
        let fragments = cmdu.clone().fragment(1500);
        assert!(fragments.len() >= 2, "Should create at least 2 fragments");

        // Check fragments continuity and flags
        for (i, frag) in fragments.iter().enumerate() {
            assert_eq!(frag.fragment, i as u8, "Fragment index should be correct");
        }

        let last = fragments.last().unwrap();
        assert!(
            last.flags & 0x80 != 0,
            "Last fragment must have EndOfMessage flag"
        );

        // Reassemble
        let reassembled = CMDU::reassemble(fragments).expect("Reassembly should succeed");

        // Compare with original
        assert_eq!(reassembled.message_type, cmdu.message_type);
        assert_eq!(reassembled.message_id, cmdu.message_id);
        assert_eq!(
            reassembled.payload, cmdu.payload,
            "Reassembled payload should match original"
        );
    }

    // Verify that no CMDU fragmentation will be used for small TLVs fitting one fragment
    #[test]
    fn test_fragment_no_fragmentation() {
        // Small CMDU with 3 TLVSs that fits in one fragment
        let cmdu = make_dummy_cmdu(vec![100, 200, 300]); // 600 bytes

        let fragments = cmdu.clone().fragment(1500);
        assert_eq!(fragments.len(), 1, "Only one fragment should be created");
        let frag = &fragments[0];

        assert_eq!(frag.fragment, 0);
        assert!(
            frag.flags & 0x80 != 0,
            "Single fragment must have EndOfMessage flag"
        );

        // Reassemble
        let reassembled = CMDU::reassemble(fragments).expect("Reassembly should succeed");

        // Compare with original
        assert_eq!(
            reassembled.payload, cmdu.payload,
            "Original and reassembled payload should match"
        );
    }

    // Verify the correctness of fragmentation and reassembly of CMDU with big TLVs
    #[test]
    fn test_fragmentation_check_fragments_size() {
        let cmdu = make_dummy_cmdu(vec![1500 - 8 - 3, 500, 900, 1500 - 8 - 3]);

        // Fragment CMDU
        let fragments = cmdu.clone().fragment(1500);
        assert!(fragments.len() >= 3, "Should create at least 3 fragments");

        // Check size of every fragment. Every CMDU fragment (including CMDU header) should have length in range of 11..1500 bytes
        for (i, frag) in fragments.iter().enumerate() {
            if frag.is_last_fragment() {
                // Differentiate between last-first and the last-but-not-first CMDU fragments
                if i == 0 {
                    // First and at the same time last CMDU fragment (the only fragment in CMDU chain) in case of size based fragmentation should have minimal size of CMDU header + TLV header without any TLV payload
                    assert!(
                        frag.total_size() >= 8 + 3,
                        "Fragment {0} should be at least 8+3 bytes but is {1} bytes long",
                        i,
                        frag.total_size()
                    );
                } else {
                    // Last CMDU fragment which is not first one - in case of size based fragmentation should have minimal size of CMDU header + 1 byte
                    assert!(
                        frag.total_size() >= 8 + 1,
                        "Fragment {0} should be at least 8+1 bytes but is {1} bytes long",
                        i,
                        frag.total_size()
                    );
                }
            }
            assert!(
                frag.total_size() <= 1500,
                "Fragment {} should have maximum 1500 bytes but is {} bytes long",
                i,
                frag.total_size()
            );
            assert_eq!(frag.fragment, i as u8, "Fragment index should be correct");
        }

        // Check if the "last fragment" flag is set in last fragment
        assert!(
            fragments.last().unwrap().flags & 0x80 != 0,
            "Last fragment must have lastFragmentIndicator flag set"
        );

        // Reassembling CMDU fragments
        let reassembled = CMDU::reassemble(fragments).expect("Reassembly should succeed");

        // Compare payloads of original CMDU and reassembled one
        assert_eq!(
            reassembled.payload, cmdu.payload,
            "Original and reassembled payload should match"
        );
    }

    // Verify the correctness of fragmentation and reassembly of CMDU with one TLV exceeding MTU
    #[test]
    fn test_a_few_fragments_with_last_one_exceeding_mtu() {
        // CMDU with one TLV exceeding MTU size
        // 1500 bytes of TLV payload + 3 bytes of TLV header exceeds maximal fragment size of 1500 bytes
        let cmdu = make_dummy_cmdu(vec![400, 500, 1500]); // 2400 bytes of TLVs payload

        // Try to do the fragmentation of CMDU
        // It should not panic in fragment() as size based fragmentation allows TLV payload bigger than MTU
        let fragments = cmdu.clone().fragment(1500);

        // Reassembly
        let reassembled = CMDU::reassemble(fragments).expect("Reassembly should succeed");

        // Compare payloads of original CMDU and reassembled one
        assert_eq!(
            reassembled.payload, cmdu.payload,
            "Original and reassembled payload should match"
        );
    }

    // Verify the correctness of fragmentation and reassembly of CMDU fitting exactly CMDU size
    #[test]
    fn test_single_cmdu_fragment_with_exact_size_of_mtu() {
        // Create single CMDU that fits exactly in one fragment
        let cmdu = make_dummy_cmdu(vec![1500 - 8 - 3]); // Whole CMDU (with CMDU header) has 1500 bytes

        // Do the fragmentation on CMDU
        let fragments = cmdu.clone().fragment(1500);
        assert_eq!(fragments.len(), 1, "Should create exactly 1 fragment");

        // Check if total size of single CMDU (first and at the same time last) meets requirement of minimal size of the fragment
        assert!(
            fragments[0].total_size() >= 8 + 3,
            "Empty CMDU payload. CMDU fragment should be at least 8+3 bytes (CMDU header + endOfMessageTlv) but is {:?} bytes long",
            fragments[0].total_size());

        // Check if total size of CMDU meets requirement of maximal size of the fragment
        assert!(
            fragments[0].total_size() <= 1500,
            "CMDU fragment should have maximum 1500 bytes but is {:?} bytes long",
            fragments[0].total_size()
        );

        // Reassembly
        let reassembled = CMDU::reassemble(fragments).expect("Reassembly should succeed");

        // Compare payloads of original CMDU and reassembled one
        assert_eq!(
            reassembled.payload, cmdu.payload,
            "Original and reassembled payload should match"
        );
    }

    // Verify fragmentation of CMDU with payload bigger than 1500 bytes
    #[test]
    fn test_fragmentation() {
        // Prepare big CMDU with TLV chain exceeding 1500 bytes
        let mut huge_cmdu = make_dummy_cmdu(vec![500, 500, 500, 500]);

        // Set LastFragmentIndicator flag on this CMDU
        huge_cmdu.flags = 0x80;

        // Do the fragmentation
        let fragmented_cmdus = huge_cmdu.fragment(1500);

        // Count number of CMDU fragments
        let no_of_fragments = fragmented_cmdus.len();

        // Expect exactly 2 CMDU fragments
        assert!(no_of_fragments == 2);

        assert!(!fragmented_cmdus.first().unwrap().is_last_fragment());
        assert!(fragmented_cmdus.last().unwrap().is_last_fragment());
    }

    // Check recognition and signalling of fragmented CMDU
    #[test]
    fn test_check_fragmented_cmdu() {
        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        let whole_payload = end_of_message_tlv.serialize();

        // Make fragmented CMDU with bit 7 unset in flags field
        let cmdu = CMDU {
            message_version: 0x01,
            reserved: 0x00,
            message_type: CMDUType::Unknown(0x08).to_u16(),
            message_id: 0x1234,
            fragment: 0x01,
            flags: 0x00, // Bit 7 must not be set to be recognized as fragmented CMDU
            payload: whole_payload,
        };
        assert!(cmdu.is_fragmented());
    }

    // Verify serializing and parsing IEEE 1905 neighbor device
    #[test]
    fn test_ieee1905_neighbor_device_parse_and_serialize() {
        let local_mac = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);

        // Make a vector with neighbor definitions
        let neighbors = vec![
            IEEE1905Neighbor {
                neighbor_al_mac: MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
                neighbor_flags: 0x01,
            },
            IEEE1905Neighbor {
                neighbor_al_mac: MacAddr::new(0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC),
                neighbor_flags: 0x02,
            },
        ];

        let device = Ieee1905NeighborDevice {
            local_mac_address: local_mac,
            neighborhood_list: neighbors.clone(),
        };

        let serialized = device.serialize();

        // neighbor_count = 2
        let parsed = Ieee1905NeighborDevice::parse(&serialized, 2);
        assert!(parsed.is_ok());

        let (_, parsed_device) = parsed.unwrap();
        assert_eq!(parsed_device.local_mac_address, local_mac);
        assert_eq!(parsed_device.neighborhood_list, neighbors);

        // Re-serialize to verify round-trip accuracy
        let reserialized = parsed_device.serialize();
        assert_eq!(serialized, reserialized);
    }

    // Verify serialization and parsing of entry without any IEEE 1905 neighbor
    #[test]
    fn test_parse_with_no_neighbors() {
        let local_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let device = Ieee1905NeighborDevice {
            local_mac_address: local_mac,
            neighborhood_list: vec![],
        };

        let serialized = device.serialize();

        let parsed = Ieee1905NeighborDevice::parse(&serialized, 0);
        assert!(parsed.is_ok());

        let (_, parsed_device) = parsed.unwrap();
        assert_eq!(parsed_device.local_mac_address, local_mac);
        assert_eq!(parsed_device.neighborhood_list.len(), 0);
    }

    // Verify parsing and serializing vendor specific info
    #[test]
    fn test_vendor_specific_info_parse_and_serialize() {
        // Simulated binary TLV value: OUI + vendor data
        let original_oui = [0x00, 0x11, 0x22];
        let vendor_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let raw_bytes: Vec<u8> = original_oui
            .iter()
            .cloned()
            .chain(vendor_data.iter().cloned())
            .collect();
        let input_length = raw_bytes.len() as u16;

        // Parse
        let result = VendorSpecificInfo::parse(&raw_bytes, input_length);
        assert!(result.is_ok(), "Parsing failed: {:?}", result);

        let (_, parsed) = result.unwrap();
        assert_eq!(parsed.oui, original_oui);
        assert_eq!(parsed.vendor_data, vendor_data);

        // Serialize
        let serialized = parsed.serialize();
        assert_eq!(
            serialized, raw_bytes,
            "Serialized output did not match input"
        );
    }

    #[test]
    fn test_cmdus_parsing_with_padding() {
        let al_mac_tlv = TLV {
            tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
            tlv_length: 6,
            tlv_value: Some(vec![0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
        };
        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        let mut payload = Vec::new();
        payload.extend(al_mac_tlv.clone().serialize());
        payload.extend(end_of_message_tlv.clone().serialize());

        // Construct the CMDU
        let cmdu_topology_discovery = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::TopologyDiscovery.to_u16(),
            message_id: 123,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload,
        };

        // Serialize the CMDU
        let mut serialized_discovery = cmdu_topology_discovery.serialize();

        // Add padding to the end of the serialized CMDU
        serialized_discovery.extend([0; 13]);

        // Parse the serialized CMDU
        let parsed_discovery = CMDU::parse(&serialized_discovery).unwrap().1;

        // Assert that the parsed CMDU matches the original
        assert_eq!(
            cmdu_topology_discovery.get_tlvs().unwrap(),
            parsed_discovery.get_tlvs().unwrap()
        );
    }

    // Verify serializing and parsing topology discovery CMDU
    #[test]
    fn test_topology_discovery_cmdus() {
        // Define the required TLVs
        let al_mac_tlv = TLV {
            tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
            tlv_length: 6,
            tlv_value: Some(vec![0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
        };

        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };
        let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(al_mac_tlv.clone().serialize());
        serialized_payload.extend(end_of_message_tlv.clone().serialize());
        // Construct the CMDU
        let cmdu_topology_discovery = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::TopologyDiscovery.to_u16(),
            message_id: 123,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload: serialized_payload,
        };

        // Serialize the CMDU
        let serialized_discovery = cmdu_topology_discovery.serialize();

        // Parse the serialized CMDU
        let parsed_discovery = CMDU::parse(&serialized_discovery).unwrap().1;

        // Assert that the parsed CMDU matches the original
        assert_eq!(cmdu_topology_discovery, parsed_discovery);
    }

    // Verify serialization and parsing of topology notification CMDU
    #[test]
    fn test_topology_notification_cmdus() {
        let al_mac_tlv = TLV {
            tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
            tlv_length: 6,
            tlv_value: Some(vec![0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
        };

        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };
        let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(al_mac_tlv.clone().serialize());
        serialized_payload.extend(end_of_message_tlv.clone().serialize());

        let cmdu_topology_notification = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::TopologyNotification.to_u16(),
            message_id: 456,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload: serialized_payload,
        };

        let serialized_notification = cmdu_topology_notification.serialize();
        let parsed_notification = CMDU::parse(&serialized_notification).unwrap().1;

        assert_eq!(cmdu_topology_notification, parsed_notification);
    }

    // Verify serializing and parsing of topology query CMDU
    #[test]
    fn test_topology_query_cmdus() {
        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        let cmdu_topology_query = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::TopologyQuery.to_u16(),
            message_id: 789,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload: end_of_message_tlv.clone().serialize(),
        };

        let serialized_query = cmdu_topology_query.serialize();
        let parsed_query = CMDU::parse(&serialized_query).unwrap().1;

        assert_eq!(cmdu_topology_query, parsed_query);
    }

    // Verify serializing and parsing of topology response CMDU
    #[test]
    fn test_topology_response_cmdus() {
        let al_mac_tlv = TLV {
            tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
            tlv_length: 6,
            tlv_value: Some(vec![0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
        };

        let mac_address_tlv = TLV {
            tlv_type: IEEE1905TLVType::MacAddress.to_u8(),
            tlv_length: 6,
            tlv_value: Some(vec![0x00, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E]),
        };

        let ieee_neighbor_device_tlv = TLV {
            tlv_type: IEEE1905TLVType::Ieee1905NeighborDevices.to_u8(),
            tlv_length: 7 * 2 + 6, // (7 bytes per neighbor * 2 neighbors) + 6 (local MAC)
            tlv_value: Some(vec![
                // Local Interface MAC Address (6 bytes)
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Neighbor 1
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0b10000000, // AL MAC + Flags
                // Neighbor 2
                0x56, 0x78, 0x9A, 0xBC, 0xCD, 0xEF, 0b10000000, // AL MAC + Flags
            ]),
        };

        let non_ieee_neighbor_device_tlv = TLV {
            tlv_type: IEEE1905TLVType::NonIeee1905NeighborDevices.to_u8(),
            tlv_length: (6 * 4), // 6 bytes (Local MAC) + 6 bytes per neighbor (3 neighbors)
            tlv_value: Some(vec![
                // Local Interface MAC Address (6 bytes)
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, // Neighbor 1
                0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, // Neighbor 2
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Neighbor 3
                0xAA, 0xBB, 0xCC, 0xDD, 0x1E, 0xFF,
            ]),
        };

        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(al_mac_tlv.clone().serialize());
        serialized_payload.extend(mac_address_tlv.clone().serialize());
        serialized_payload.extend(ieee_neighbor_device_tlv.clone().serialize()); // IEEE 1905 Neighbor Devices TLV
        serialized_payload.extend(non_ieee_neighbor_device_tlv.clone().serialize()); // Non-IEEE 1905 Neighbor Devices TLV
        serialized_payload.extend(end_of_message_tlv.clone().serialize());

        let cmdu_topology_response = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::TopologyResponse.to_u16(),
            message_id: 123,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload: serialized_payload,
        };

        let serialized_response = cmdu_topology_response.serialize();
        let parsed_response = CMDU::parse(&serialized_response).unwrap().1;

        assert_eq!(cmdu_topology_response, parsed_response);
    }

    // Verify serializing and parsing of AP autoconfig search CMDU
    #[test]
    fn test_ap_autoconfig_search_cmdus() {
        // Creation of the TLV searched role
        let searched_role_value = SearchedRole { role: 0x00 }; // 0x00 is registrar
        let searched_role_tlv = TLV {
            tlv_type: IEEE1905TLVType::SearchedRole.to_u8(),
            tlv_length: 1,
            tlv_value: Some(searched_role_value.serialize()),
        };

        // EoM
        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(searched_role_tlv.clone().serialize());
        serialized_payload.extend(end_of_message_tlv.clone().serialize());

        // we build the CMDU
        let cmdu_autoconfig_search = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::ApAutoConfigSearch.to_u16(),
            message_id: 42,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload: serialized_payload,
        };

        // Serializing
        let serialized_cmdus = cmdu_autoconfig_search.serialize();
        let parsed_cmdus = CMDU::parse(&serialized_cmdus).unwrap().1;

        // Verification
        assert_eq!(cmdu_autoconfig_search, parsed_cmdus);
    }

    // Verify serializing ans parsing AP autoconfig response CMDU
    #[test]
    fn test_ap_autoconfig_response_cmdus() {
        // Creation of TLV SupportedRole
        let supported_role_value = SupportedRole { role: 0x00 }; // WE use registrar value
        let supported_role_tlv = TLV {
            tlv_type: IEEE1905TLVType::SupportedRole.to_u8(),
            tlv_length: 1,
            tlv_value: Some(supported_role_value.serialize()),
        };

        // TLV EoM
        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(supported_role_tlv.clone().serialize());
        serialized_payload.extend(end_of_message_tlv.clone().serialize());
        // we build ApAutoConfigResponse
        let cmdu_autoconfig_response = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::ApAutoConfigResponse.to_u16(),
            message_id: 99,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload: serialized_payload,
        };

        // serialization and parsing
        let serialized_cmdus = cmdu_autoconfig_response.serialize();
        let parsed_cmdus = CMDU::parse(&serialized_cmdus).unwrap().1;

        // Verification
        assert_eq!(cmdu_autoconfig_response, parsed_cmdus);
    }

    // Verify serializing and parsing AP autoconfig search CMDU with proper role
    #[test]
    fn test_ap_autoconfig_search_with_proper_role() {
        let searched_role_value = SearchedRole { role: 0x00 };
        let searched_role_tlv = TLV {
            tlv_type: IEEE1905TLVType::SearchedRole.to_u8(),
            tlv_length: 1,
            tlv_value: Some(searched_role_value.serialize()),
        };

        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };
        let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(searched_role_tlv.clone().serialize());
        serialized_payload.extend(end_of_message_tlv.clone().serialize());
        let cmdu = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::ApAutoConfigSearch.to_u16(),
            message_id: 43,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload: serialized_payload,
        };

        let serialized = cmdu.serialize();
        let parsed = CMDU::parse(&serialized).unwrap().1;

        let tlvs = parsed.get_tlvs().unwrap();
        let searched_tlv = tlvs
            .iter()
            .find(|tlv| tlv.tlv_type == IEEE1905TLVType::SearchedRole.to_u8())
            .expect("SearchedRole TLV not found");

        let value = searched_tlv
            .tlv_value
            .as_ref()
            .expect("SearchedRole TLV has no value");

        let result = SearchedRole::parse(value, searched_tlv.tlv_length);

        assert!(result.is_ok());
    }

    // Verify serializing and parsing valid role
    #[test]
    fn test_supported_role_parse_and_serialize() {
        let role = SupportedRole { role: 0x00 };
        let serialized = role.serialize();
        //        let parsed = SupportedRole::parse(&serialized.clone()[..], serialized.len() as u16);
        let parsed = SupportedRole::parse(&serialized[..], serialized.len() as u16);

        // Expect that parsing succeed
        assert_eq!(role, parsed.unwrap().1);
    }

    // Verify serializing and parsing CMDU with empty TLV list
    #[test]
    fn test_single_cmdu_fragment_without_tlv() {
        // Make CMDU with empty TLV list
        let cmdu = make_dummy_cmdu(vec![]);

        let serialized = cmdu.serialize();
        let parsed = CMDU::parse(&serialized);

        // CMDU parsing and serializing should succeed
        assert!(parsed.is_ok());

        // Compare original CMDU with the one processed by serializer and parser
        assert_eq!(cmdu, parsed.unwrap().1);
    }

    // Verify parsing and serializing cycle on LocalInterface data
    #[test]
    fn test_local_interface_parse_and_serialize() {
        // Create slice with raw data to parse: MAC address (6 bytes) + media type (2 bytes) + special info (1 byte)
        let data = &[0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02, 0x00, 0x01, 0x00];

        // Parse LocalInterface data
        let local_interface = LocalInterface::parse(data).unwrap();

        // Expect success comparing parsed and then serialized data with original ones
        assert_eq!(local_interface.1.serialize(), data);

        // Subtest using LocalInterface::new()
        let mac: MacAddr = MacAddr(0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02);
        let media_type: u16 = 0x01; // Set ethernet type
        let special_info: Vec<u8> = vec![]; // Empty "special info" data
        let local_interface = LocalInterface::new(mac, media_type, special_info);

        // Expect success comparing serialized data and original
        assert_eq!(local_interface.serialize(), data);
    }

    // Verify parsing and serializing of DeviceInformation data
    #[test]
    fn test_device_information_parse_and_serialize() {
        // Mac address + ethernet (0x00, 0x01) as media type + 0x00 as special info
        let data = &[0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02, 0x00, 0x01, 0x00];
        let local_interface = LocalInterface::parse(data).unwrap();
        let mac = MacAddr::new(0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02);
        let device_information = DeviceInformation::new(mac, vec![local_interface.1]);

        let serialized = device_information.serialize();
        let len = serialized.len() as u16;

        // Expect that parsing DeviceInformation data succeed
        match DeviceInformation::parse(&serialized, len) {
            Ok((_, parsed)) => {
                assert_eq!(serialized, parsed.serialize());
            }
            Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) | Err(NomErr::Failure(_)) => {
                panic!("Parsing of serialized data should succeed, but it didn't");
            }
        }
    }

    // Verify serializing and parsing valid BridgingTuple data
    #[test]
    fn test_bridging_tuple_parse_and_serialize() {
        // Create BridgingTuple raw data: 0x01 as number of MAC addresses + MAC address value
        let data = &[0x01, 0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];

        // Parse the BridgingTuple data
        let bridging_tuple = BridgingTuple::parse(data).unwrap();

        // Serialize just parsed BridgingTuple structure
        let serialized = bridging_tuple.1.serialize();

        // Expect success parsing the serialized earlier BridgingTuple data
        match BridgingTuple::parse(&serialized) {
            Ok((_, parsed)) => {
                assert_eq!(serialized, parsed.serialize());
            }
            Err(nom::Err::Incomplete(_)) | Err(NomErr::Failure(_)) | Err(nom::Err::Error(_)) => {
                panic!("Parsing of serialized data should succeed, but it didn't")
            }
        };
    }

    // Verify serializing and parsing DeviceBridgingCapability data
    #[test]
    fn test_device_bridging_capability_parse_and_serialize() {
        // Create BridgingTuple raw data: 0x01 as number of MAC addresses + MAC address value
        let bridging_tuple_data = &[0x01, 0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];

        // Parse the BridgingTuple data
        let bridging_tuple = BridgingTuple::parse(bridging_tuple_data).unwrap();

        // Serialize just parsed BridgingTuple structure
        let serialized = bridging_tuple.1.serialize();

        // Prepare number of bridging tuples (0x01) for DeviceBridgingCapability
        let mut bridging_capability: Vec<u8> = vec![0x01];

        // Append BridgingTuple data to DeviceBridgingCapability as bridging_tuples_list
        bridging_capability.append(&mut serialized.clone());

        // Parse the vector of data as DeviceBridgingCapability
        let parsed = DeviceBridgingCapability::parse(&bridging_capability)
            .unwrap()
            .1;

        // Expect that serialized DeviceBridgingCapability matches original bridging_capability
        assert_eq!(
            parsed.serialize(),
            bridging_capability,
            "Serialized data should be equal to original"
        );
    }

    // Verify serializing and parsing NonIEEE1905Neighbor data
    #[test]
    fn test_non_ieee1905_neighbor_parse_and_serialize() {
        // Example MAC address
        let mac = &[0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];

        // Parse example MAC address
        let parsed = NonIEEE1905Neighbor::parse(mac).unwrap().1;

        // Expect that serialized NonIEEE1905Neighbor data matches example MAC address
        assert_eq!(parsed.serialize(), mac);
    }

    // Verify serializing and parsing NonIEEE1905LocalInterfaceNeighborhood data
    #[test]
    fn test_non_ieee1905_local_interface_neighborhood_parse_and_serialize() {
        // Example local MAC address
        let local_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];

        // Example non IEEE 1905 neighbor MAC address
        let neighbor_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x03];

        let mut neighborhood = local_mac;

        // Append example non IEEE 1905 neighbor MAC address to local MAC to make NonIEEE1905LocalInterfaceNeighborhood
        neighborhood.append(&mut neighbor_mac.clone());

        // Parse vector of raw bytes as NonIEEE1905LocalInterfaceNeighborhood
        let parsed = NonIEEE1905LocalInterfaceNeighborhood::parse(&neighborhood[..], 1)
            .unwrap()
            .1;

        // Expect that the serialized NonIEEE1905LocalInterfaceNeighborhood matches original neighborhood
        assert_eq!(parsed.serialize(), neighborhood);
    }

    // Verify parsing and serializing of NonIeee1905NeighborDevices data
    #[test]
    fn test_non_ieee1905_neighbor_devices_parse_and_serialize() {
        // Example local MAC address
        let local_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];

        // Example non IEEE 1905 neighbor MAC address
        let neighbor_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x03];

        let mut neighbor_devices: Vec<u8> = local_mac;

        // Append example non IEEE 1905 neighbor MAC address to local MAC to make NonIeee1905NeighborDevices
        neighbor_devices.append(&mut neighbor_mac.clone());

        // Parse vector of raw bytes as NonIeee1905NeighborDevices
        let parsed = NonIeee1905NeighborDevices::parse(&neighbor_devices, 1)
            .unwrap()
            .1;

        // Expect that the serialized NonIeee1905NeighborDevices matches original neighbor_devices
        assert_eq!(parsed.serialize(), neighbor_devices);
    }

    // Verify parsing and serializing AL MAC address
    #[test]
    fn test_al_mac_address_parse_and_serialize() {
        // Prepare example local MAC address
        let al_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];

        // Parse provided example data as AL MAC address
        let parsed = AlMacAddress::parse(&al_mac[..]).unwrap().1;

        // Expect success comparing parsed and then serialized AL MAC address with original one
        assert_eq!(parsed.serialize(), al_mac);
    }

    // Verify parsing and serializing MAC address
    #[test]
    fn test_mac_address_parse_and_serialize() {
        // Prepare example vector with valid MAC address
        let mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];

        // Do the parsing as MacAddress
        let parsed = MacAddress::parse(&mac[..]).unwrap().1;

        // Expect success comparing parsed and then serialized MAC address with original one
        assert_eq!(parsed.serialize(), mac);
    }

    // Verify parsing incomplete data (only 5 bytes from 6 required for MAC address) as AlMacAddress
    #[test]
    fn test_mac_address_try_to_parse_not_enough_data() {
        let mac = [0x02, 0x42, 0xc0, 0xa8, 0x64];
        assert!(MacAddress::parse(&mac).is_err());
    }

    // Unit tests using malformed data

    // Try to parse invalid vendor specific info element (not enough data for OUI)
    #[test]
    fn test_vendor_specific_info_parse_invalid_length() {
        // Only 2 bytes of OUI provided (invalid). Should be 3 bytes.
        let input = vec![0x01, 0x02];
        let input_length = input.len() as u16;

        // Expect failure as the OUI is too short (2 bytes instead of 3)
        let result = VendorSpecificInfo::parse(&input, input_length);
        assert!(
            result.is_err(),
            "Expected parsing to fail due to insufficient length"
        );
    }

    // Try to serialize and parse AP autoconfig search CMDU with invalid role
    #[test]
    fn test_ap_autoconfig_search_with_invalid_role_should_fail() {
        use nom::error::ErrorKind;
        use nom::Err;

        let searched_role_value = SearchedRole { role: 0x01 };
        let searched_role_tlv = TLV {
            tlv_type: IEEE1905TLVType::SearchedRole.to_u8(),
            tlv_length: 1,
            tlv_value: Some(searched_role_value.serialize()),
        };

        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };
        let mut serialized_payload: Vec<u8> = vec![];
        serialized_payload.extend(searched_role_tlv.clone().serialize());
        serialized_payload.extend(end_of_message_tlv.clone().serialize());
        let cmdu = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::ApAutoConfigSearch.to_u16(),
            message_id: 43,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload: serialized_payload,
        };

        let serialized = cmdu.serialize();
        let parsed = CMDU::parse(&serialized).unwrap().1;

        let tlvs = parsed.get_tlvs().unwrap();
        let searched_tlv = tlvs
            .iter()
            .find(|tlv| tlv.tlv_type == IEEE1905TLVType::SearchedRole.to_u8())
            .expect("SearchedRole TLV not found");

        let value = searched_tlv
            .tlv_value
            .as_ref()
            .expect("SearchedRole TLV has no value");

        let result = SearchedRole::parse(value, searched_tlv.tlv_length);

        match result {
            Err(Err::Failure(e)) => assert_eq!(e.code, ErrorKind::Verify),
            Ok(_) => panic!(
                "Expected failure due to invalid role value (not 0x00), but parsing succeeded."
            ),
            Err(e) => panic!("Expected Failure(Verify), but got different error: {:?}", e),
        }
    }

    // Try to parse invalid role
    #[test]
    fn test_supported_role_invalid_role() {
        let role = SupportedRole { role: 0x01 };
        let serialized = role.serialize();
        let parsed = SupportedRole::parse(&serialized[..], serialized.len() as u16);

        // Expect ErrorKind::Verify because role 0x01 is not valid
        match parsed {
            Err(nom::Err::Failure(e)) => assert_eq!(e.code, ErrorKind::Verify),
            Ok(_) => panic!(
                "Expected failure due to invalid role value (not 0x00), but parsing succeeded."
            ),
            Err(e) => panic!("Expected Failure(Verify), but got different error: {:?}", e),
        }
    }

    // Try to serialize and parse unknown CMDU type
    #[test]
    fn test_unknown_cmdus() {
        let unknown_tlvs: Vec<TLV> = (0..6)
            .map(|i| TLV {
                tlv_type: 0xA0 + i, // Arbitrary unknown TLV types
                tlv_length: 4,
                tlv_value: Some(vec![i, (i + 1), (i + 2), (i + 3)]),
            })
            .collect();

        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        let mut serialized_payload: Vec<u8> = vec![];
        for tlv in unknown_tlvs {
            serialized_payload.extend(tlv.serialize());
        }
        serialized_payload.extend(end_of_message_tlv.clone().serialize());

        // Create CMDU of unknown type
        let cmdu_unknown = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: 0xFFFF, // Unknown CMDUType
            message_id: 999,
            fragment: 0,
            flags: 0x80, // Single not fragmented CMDU - set lastFragmentIndicator flag
            payload: serialized_payload,
        };

        let serialized_unknown = cmdu_unknown.serialize();
        let parsed_unknown = CMDU::parse(&serialized_unknown).unwrap().1;

        assert_eq!(cmdu_unknown, parsed_unknown);
    }

    // Try to parse slice with not enough of data for LocalInterface
    #[test]
    fn test_local_interface_parse_too_small_data() {
        // Prepare slice with not enough data to parse (7 bytes only)
        let data = &[1, 2, 3, 4, 5, 6, 7];

        // Expect ErrorKind::Eof error trying to parse provided too small slice of data
        match LocalInterface::parse(data) {
            Err(NomErr::Failure(err)) => {
                assert_eq!(err.code, ErrorKind::Eof)
            }
            Ok(_) | Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => {
                panic!("ErrorKind::Eof should be returned");
            }
        }
    }

    // Try to parse DeviceInformation data with redundant, not needed dummy byte: 0xFF
    #[test]
    fn test_device_information_try_to_parse_too_many_data() {
        let mut local_interface_data: Vec<u8> =
            vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02, 0x00, 0x01, 0x00];

        // Compose DeviceInformation from: MAC address + number of local interfaces + list of local interfaces
        let mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let mut device_information_data: Vec<u8> = mac;

        // Set number of local interfaces to 1
        device_information_data.push(0x1);

        // Append LocalInterface data
        device_information_data.append(&mut local_interface_data);

        // Add dummy, not needed byte 0xFF
        device_information_data.push(0xff);

        let len = device_information_data.len() as u16;

        // Expect LenghtValue error trying to parse the DeviceInformation data because of one dummy, not needed byte: 0xFF
        match DeviceInformation::parse(device_information_data.as_slice(), len) {
            Err(NomErr::Failure(err)) => {
                assert_eq!(err.code, ErrorKind::LengthValue);
            }
            Ok((_, _)) | Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => {
                panic!("Failure::LengthValue should be returned")
            }
        };
    }

    // Verify trying to parse not complete (too short) BridgingTuple data
    #[test]
    fn test_bridging_tuple_not_enough_data() {
        // One MAC address counter + trimmed MAC address to 5 bytes
        let data = &[0x01, 0x02, 0x42, 0xc0, 0xa8, 0x64];

        // Try to parse not enough data for BridgingTuple
        let bridging_tuple = BridgingTuple::parse(data);

        // Expect ErrorKind::Eof error after trying to parse not complete BridgingTuple data
        match bridging_tuple {
            Err(NomErr::Failure(err)) => {
                assert_eq!(err.code, ErrorKind::Eof);
            }
            Ok(_) | Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => {
                panic!("ErrorKind::Eof should be returned")
            }
        }
    }

    // Verify parsing incomplete data (only 5 bytes from 6 required for local MAC address) as NonIeee1905NeighborDevices
    #[test]
    fn test_non_ieee1905_neighbor_devices_not_enough_data_5_bytes() {
        // Prepare example vector with bad, shortened local MAC address data to 5 bytes
        let partial_local_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64];
        let neighbor_devices: Vec<u8> = partial_local_mac;

        // Try to parse vector with not enough of data as NonIeee1905NeighborDevices
        let parsed = NonIeee1905NeighborDevices::parse(&neighbor_devices, 1);

        // Expect ErrorKind::Eof error after trying to parse incomplete data as NonIeee1905NeighborDevices
        match parsed {
            Err(NomErr::Error(err)) => {
                println!("errcode___: {:?}", err.code);
                assert_eq!(err.code, ErrorKind::Eof)
            }
            Ok(_) | Err(nom::Err::Incomplete(_)) | Err(nom::Err::Failure(_)) => {
                panic!("ErrorKind::Eof should be returned");
            }
        }
    }

    // Verify parsing incomplete data (11 bytes from 12 required for local MAC and neighbor MAC addresses) as NonIeee1905NeighborDevices
    #[test]
    fn test_non_ieee1905_neighbor_devices_not_enough_data_11_bytes() {
        // Prepare example full local MAC address (6 bytes)
        let local_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];

        // Prepare example bad, shortened to 5 bytes neighbor MAC address
        let neighbor_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64];

        // Make contents of NonIeee1905NeighborDevices for parsing
        let mut neighbor_devices: Vec<u8> = local_mac;
        neighbor_devices.append(&mut neighbor_mac.clone());

        // Try to parse invalid (incomplete) data and expect ErrorKind::Eof error
        let parsed = NonIeee1905NeighborDevices::parse(&neighbor_devices, 1);

        // Expect ErrorKind::Eof error after trying to parse incomplete data as NonIeee1905NeighborDevices
        match parsed {
            Err(NomErr::Error(err)) => {
                assert_eq!(err.code, ErrorKind::Eof)
            }
            Ok(_) | Err(nom::Err::Incomplete(_)) | Err(nom::Err::Failure(_)) => {
                panic!("ErrorKind::Eof should be returned");
            }
        }
    }

    // Verify parsing incomplete data (only 5 bytes from 6 required for MAC address) as AlMacAddress
    #[test]
    fn test_al_mac_address_try_to_parse_not_enough_data() {
        // Prepare example vector with bad, shortened local MAC address data to 5 bytes
        let al_mac = [0x02, 0x42, 0xc0, 0xa8, 0x64];

        // Expect error trying to parse 5 bytes instead of required 6
        assert!(AlMacAddress::parse(&al_mac).is_err());
    }

    // Verify returning redundant data after parsing AlMacAddress
    #[test]
    fn test_al_mac_address_try_to_parse_too_much_data() {
        // Prepare example vector with valid AL MAC address
        let al_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let mut data: Vec<u8> = al_mac.clone();

        // Add redundant byte which should be returned by parser as unparsed part of the passed input
        data.push(0x11);

        // Do the parsing as AlMacAddress
        let (rest, _) = AlMacAddress::parse(&data[..]).unwrap();

        // Expect slice with 0x11 value as redundant data after parsing
        assert_eq!(rest, &[0x11]);
    }

    // Verify returning redundant data after parsing MacAddress
    #[test]
    fn test_mac_address_try_to_parse_too_much_data() {
        // Prepare example vector with valid MAC address
        let mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let mut data: Vec<u8> = mac.clone();

        // Add redundant byte which should be returned by parser as unparsed part of the passed input
        data.push(0x11);

        // Do the parsing as MacAddress
        let (rest, _) = MacAddress::parse(&data[..]).unwrap();

        // Expect slice with 0x11 value as redundant data after parsing
        assert_eq!(rest, &[0x11]);
    }

    // Verify detection and signalling of mismatch between declared tlv_length and the real length of TLV's payload
    #[test]
    fn test_get_tlvs_too_short_data() {
        // Make CMDU with two small TLVs
        let cmdu = make_dummy_cmdu(vec![100, 200]);

        // Prepare additional invalid TLV with payload length (1) that doesn't match tlv_length (100)
        let bad_tlv_length = TLV {
            tlv_type: IEEE1905TLVType::VendorSpecificInfo.to_u8(),
            tlv_length: 100,
            tlv_value: Some(vec![1]),
        };

        // Do the serialization
        let cmdu_serialized = cmdu.serialize();
        let mut cmdu_payload_extended = cmdu_serialized.clone();

        // Extend CMDU with invalid additional TLV
        cmdu_payload_extended.append(&mut bad_tlv_length.serialize());
        let (_, cmdu_parsed) = CMDU::parse(cmdu_payload_extended.as_slice()).unwrap();

        // Expect panic as the bad_tlv_length.tlv_length (100) doesn't match the real TLV payload length (1)
        assert!(cmdu_parsed.get_tlvs().is_err());
    }

    // Verify fragmentation and reassembly on CMDU with size of 1501 bytes
    #[test]
    fn test_single_cmdu_fragment_with_size_of_mtu_plus_one() {
        // Single CMDU that exceeds MTU (1500 bytes) by one byte
        let cmdu = make_dummy_cmdu(vec![1500 - 8 - 3 + 1]); // Whole CMDU (with CMDU header) has 1501 bytes

        // Do the fragmentation on CMDU
        let fragments = cmdu.clone().fragment(1500);

        for (i, frag) in fragments.iter().enumerate() {
            if frag.is_last_fragment() {
                // Differentiate between last-first and the last-but-not-first CMDU fragments
                if i == 0 {
                    // First and at the same time last CMDU fragment (the only fragment in CMDU chain) in case of size based fragmentation should have minimal size of CMDU header + TLV header without any TLV payload
                    assert!(
                        frag.total_size() >= 8 + 3,
                        "Fragment {0} should be at least 8+3 bytes but is {1} bytes long",
                        i,
                        frag.total_size()
                    );
                } else {
                    // Last CMDU fragment which is not first one - in case of size based fragmentation should have minimal size of CMDU header + 1 byte
                    assert!(
                        frag.total_size() >= 8 + 1,
                        "Fragment {0} should be at least 8+1 bytes but is {1} bytes long",
                        i,
                        frag.total_size()
                    );
                }
            }
            assert!(
                frag.total_size() <= 1500,
                "Fragment {} should have maximum 1500 bytes but is {} bytes long",
                i,
                frag.total_size()
            );
            assert_eq!(frag.fragment, i as u8, "Fragment index should be correct");
        }

        // Check if the "last fragment" flag is set in last fragment
        assert!(
            fragments.last().unwrap().flags & 0x80 != 0,
            "Last fragment must have LastFragmentIndicator flag set"
        );

        // Reassembling CMDU fragments
        let reassembled = CMDU::reassemble(fragments).expect("Reassembly should succeed");

        // Compare payloads of original CMDU and reassembled one
        assert_eq!(
            reassembled.payload, cmdu.payload,
            "Original and reassembled payload should match"
        );
    }

    // Verify recognizing and signalling of "empty fragments" condition
    #[test]
    fn test_empty_fragment_list() {
        let fragments: Vec<CMDU> = Vec::new();

        // Trying to reassemble empty fragment should return EmptyFragments error
        let reassembled = CMDU::reassemble(fragments)
            .expect_err("Reassembly shouldn't succeed on empty fragment list");

        // Expect EmptyFragments error
        assert_eq!(reassembled, CmduReassemblyError::EmptyFragments);
    }

    // Verify recognizing and signalling of "inconsistent metadata" condition
    #[test]
    fn test_inconsistent_data() {
        let cmdu1 = make_dummy_cmdu(vec![100, 200, 300]);
        let mut cmdu2 = make_dummy_cmdu(vec![400, 500, 600]);

        // Override message_id with a value different than default 0x1234 to make CMDU fragments chain inconsistent
        cmdu2.message_id = 0x6789;

        // Make a chain of CMDUs
        let fragments: Vec<CMDU> = vec![cmdu1, cmdu2];

        // Trying to reassemble inconsistent CMDU chain should return error: InconsistentMetadata
        let reassembled = CMDU::reassemble(fragments)
            .expect_err("Reassembly shouldn't succeed on inconsistent CMDUs");

        // Expect InconsistentMetadata error
        assert_eq!(reassembled, CmduReassemblyError::InconsistentMetadata);
    }

    // Verify lack of CMDU fragment in CMDU chain
    #[test]
    fn test_missing_fragments() {
        let mut cmdu1 = make_dummy_cmdu(vec![100, 200, 300]);
        let mut cmdu2 = make_dummy_cmdu(vec![400, 500, 600]);

        // Override fragment_id with a not consecutive values
        cmdu1.fragment = 0x0;

        // Enforce fragment No. 2 to simulate missing fragment No. 1
        cmdu2.fragment = 0x2;

        // Make CMDU chain
        let fragments: Vec<CMDU> = vec![cmdu1, cmdu2];
        let reassembled = CMDU::reassemble(fragments)
            .expect_err("Reassembly shouldn't succeed on missed fragment");

        assert_eq!(reassembled, CmduReassemblyError::MissingFragments);
    }

    #[test]
    fn test_unknown_tlv() {
        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 1, // Set wrong length as 1 but should be 0 as tlv_value == None below
            tlv_value: None,
        };

        let cmdu_topology_query = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::TopologyQuery.to_u16(),
            message_id: 789,
            fragment: 0,
            flags: 0x80, // Not fragmented
            payload: end_of_message_tlv.clone().serialize(),
        };

        let serialized_query = cmdu_topology_query.serialize();
        let parsed_query_result = CMDU::parse(&serialized_query);

        assert!(parsed_query_result.is_err());
    }

    // Check detection and signalling of missing last fragment in CMDU fragments chain
    #[test]
    fn test_missing_end_of_message() {
        let mut cmdu1 = make_dummy_cmdu(vec![100, 200, 300]);
        let mut cmdu2 = make_dummy_cmdu(vec![400, 500, 600]);

        // Override fragment_id with consecutive values
        cmdu1.fragment = 0x0;
        cmdu2.fragment = 0x1;

        // Override flags field with value with bit 7 (lastFragmentIndicator) cleared to simulate missing last fragment
        cmdu1.flags = 0x0;
        cmdu2.flags = 0x0;

        // Make CMDU chain
        let fragments: Vec<CMDU> = vec![cmdu1, cmdu2];

        // Trying to parse CMDU chain should result in error: MissingLastFragment
        let reassembled = CMDU::reassemble(fragments)
            .expect_err("Reassembly shouldn't succeed on missed LastFragment flag");

        // Expect MissingLastFragment error
        assert_eq!(reassembled, CmduReassemblyError::MissingLastFragment);
    }

    // Test sequence of CMDU fragments that arrived out of order.
    #[test]
    fn test_out_of_order_fragments() {
        let mut cmdu0 = make_dummy_cmdu(vec![10, 20]);
        let mut cmdu1 = make_dummy_cmdu(vec![30, 40]);
        let mut cmdu2 = make_dummy_cmdu(vec![50, 60]);

        cmdu0.fragment = 0;
        cmdu1.fragment = 1;
        cmdu2.fragment = 2;

        // Set last fragment flag
        cmdu2.flags = 0x80;

        // Prepare vector with out of order CMDU fragments
        let fragments: Vec<CMDU> = vec![cmdu0, cmdu2, cmdu1];

        // Pass the vector with out of order CMDUs
        let reassembled = CMDU::reassemble(fragments);
        assert!(reassembled.is_ok());

        // Verify the length of reassembled CMDU payload which is sum of 6 TLV headers and their payload
        // 6 TLVs data take 210 bytes and additional 6 TLV headers takes 3 bytes each
        assert_eq!(
            reassembled.clone().unwrap().payload.len(),
            10 + 20 + 30 + 40 + 50 + 60 + 6 * 3
        );

        // Verify if the data from out of order CMDUs are in proper order after reassembly.
        let mut offset = 0;

        // Define vector of sizes of consecutive TLVs for verification (from already sorted CMDUs)
        let sizes = vec![10, 20, 30, 40, 50, 60];

        // Iter on all the TLVs and check their size with the predefined vector "sizes"
        for i in sizes.iter() {
            let chunk = &reassembled.clone().unwrap().payload[offset..offset + 3 + i];
            assert_eq!(TLV::parse(chunk).unwrap().1.tlv_length, *i as u16);

            // Move offset to the next chunk: size of current TLV payload + TLV header length
            offset += i + 3;
        }
    }

    // Test if CMDU reassembly procedure reports missed CMDU fragment
    #[test]
    fn test_missed_one_fragment() {
        let mut cmdu0 = make_dummy_cmdu(vec![10, 20]);
        let mut cmdu1 = make_dummy_cmdu(vec![30, 40]);
        let mut cmdu2 = make_dummy_cmdu(vec![50, 60]);
        let mut cmdu3 = make_dummy_cmdu(vec![70, 80]);

        // Create CMDU fragments chain with missing fragment No. 2
        cmdu0.fragment = 0;
        cmdu1.fragment = 1;
        cmdu2.fragment = 3; // Skip fragment 2 and set fragment to id = 3
        cmdu3.fragment = 4;

        // Set last fragment flag
        cmdu3.flags = 0x80;

        // Prepare vector with CMDU fragments
        let fragments: Vec<CMDU> = vec![cmdu0, cmdu1, cmdu2, cmdu3];
        let reassembled = CMDU::reassemble(fragments);

        // Expect MissingFragments error
        assert_eq!(
            CmduReassemblyError::MissingFragments,
            reassembled.unwrap_err()
        );
    }
}
