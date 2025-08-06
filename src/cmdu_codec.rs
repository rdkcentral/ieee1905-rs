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
            //TO do remove this linkMetric
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
    pub fn parse(input: &[u8], input_length: u16) -> IResult<&[u8], Self> {
        //let (input, mac_bytes) = take(6usize)(input)?;
        let (input, mac_bytes) = take(input_length as usize)(input)?;

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
    pub fn parse(input: &[u8], input_length: u16) -> IResult<&[u8], Self> {
        //let (input, mac_bytes) = take(6usize)(input)?;
        let (input, mac_bytes) = take(input_length as usize)(input)?;

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
    #[cfg(feature = "size_based_fragmentation")]
    pub payload: Vec<u8>,
    #[cfg(not(feature = "size_based_fragmentation"))]
    pub payload: Vec<TLV>,
}
impl CMDU {
    pub fn get_tlvs(self) -> Vec<TLV> {
        #[cfg(not(feature = "size_based_fragmentation"))]
        return self.payload;
        #[cfg(feature = "size_based_fragmentation")]
        {
            let mut tlvs: Vec<TLV> = vec![];
            let mut remaining_input = self.payload.as_slice();
            let mut has_reached_end = false;
            while !remaining_input.is_empty() && !has_reached_end {
                //tracing::trace!("Remaining input {:?}", remaining_input);
                //let (next_input, tlv) = TLV::parse(remaining_input)?;
                match TLV::parse(remaining_input) {
                    Ok(tlv) => {
                        tracing::trace!("Parsed TLV {:?}", tlv.1);
                        /* The minimum Ethernet frame length (over the wire) is 60 bytes
                         * For very small frames like Topology Discovery, it is likely
                         * there will be zero padding after the content of the frame
                         */
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
                        panic!("Failed to parse TLV: {e:?}. Unparseable data: <{hex_string:?}>");
                    }
                }
            }
            tlvs
        }
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
        #[cfg(feature = "size_based_fragmentation")]
        let remaining_input: &[u8] = &[];

        #[cfg(not(feature = "size_based_fragmentation"))]
        let mut payload: Vec<TLV> = Vec::new();
        #[cfg(not(feature = "size_based_fragmentation"))]
        let mut remaining_input = input;
        #[cfg(not(feature = "size_based_fragmentation"))]
        let mut has_reached_end = false;

        tracing::trace!("CMDU_parse: message_version {message_version:?}, reserved {reserved:?},
                         message_type: {message_type:?}, message_id {message_id:?}, fragment: {fragment:?}");
        // Since in size based fragmentation remaining input might have incomplete TLV's
        // there is no need to analyze TLV's as it's impossible to match them here.
        // so we will be reading max  bytes
        // and we will push it deeper.
        #[cfg(feature = "size_based_fragmentation")]
        {
            tracing::trace!(
                "Returning CMDU. Might have incomplete TLV's due to size fragmentation"
            );
            Ok((
                remaining_input,
                Self {
                    message_version,
                    reserved,
                    message_type,
                    message_id,
                    fragment,
                    flags,
                    payload: input.into(),
                },
            ))
        }
        #[cfg(not(feature = "size_based_fragmentation"))]
        {
            while !remaining_input.is_empty() && !has_reached_end {
                //tracing::trace!("Remaining input {:?}", remaining_input);
                //let (next_input, tlv) = TLV::parse(remaining_input)?;
                match TLV::parse(remaining_input) {
                    Ok(tlv) => {
                        tracing::trace!("Parsed TLV {:?}", tlv.1);
                        /* The minimum Ethernet frame length (over the wire) is 60 bytes
                         * For very small frames like Topology Discovery, it is likely
                         * there will be zero padding after the content of the frame
                         */
                        if tlv.1.tlv_type == IEEE1905TLVType::EndOfMessage.to_u8()
                            && tlv.1.tlv_length == 0
                            && tlv.1.tlv_value.is_none()
                        {
                            has_reached_end = true;
                        }
                        payload.push(tlv.1);
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
                        return Err(NomErr::Failure(Error::new(input, ErrorKind::Fail)));
                    }
                }
            }
            let no_tlvs = payload.len();
            tracing::trace!("CMDU_Parse: number of tlvs: {no_tlvs:?}");
            // Check if the last TLV is a valid EndOfMessage TLV
            if let Some(tlv) = payload.last() {
                if tlv.tlv_type == IEEE1905TLVType::EndOfMessage.to_u8()
                    && tlv.tlv_length == 0
                    && tlv.tlv_value.is_none()
                {
                    tracing::trace!("CMDU_parse: returning valid CMDU");

                    Ok((
                        remaining_input,
                        Self {
                            message_version,
                            reserved,
                            message_type,
                            message_id,
                            fragment,
                            flags,
                            payload,
                        },
                    ))
                } else {
                    tracing::error!("CMDU_Parse: the last TLV is not end of message type.");
                    Err(NomErr::Failure(Error::new(input, ErrorKind::Tag)))
                }
            } else {
                tracing::error!("CMDU_Parse: there is no last element in payload");
                Err(NomErr::Failure(Error::new(input, ErrorKind::Eof)))
            }
        }
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
        #[cfg(feature = "size_based_fragmentation")]
        bytes.extend_from_slice(self.payload.as_slice());

        // Serialize the payload (list of TLVs)
        #[cfg(not(feature = "size_based_fragmentation"))]
        {
            for tlv in &self.payload {
                bytes.extend_from_slice(&tlv.serialize());
            }
        }

        bytes
    }

    #[cfg(feature = "size_based_fragmentation")]
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
        if let Some(last_elem) = fragments.last_mut(){
            last_elem.flags |= 0x80;
        }
        fragments
    }

    #[cfg(not(feature = "size_based_fragmentation"))]
    pub fn fragment(mut self, max_size: usize) -> Vec<CMDU> {
        // Estimate total size: 8 bytes for header + all TLVs
        let tlvs_size: usize = self
            .payload
            .iter()
            .map(|tlv| 3 + tlv.tlv_length as usize)
            .sum();
        let total_size = 8 + tlvs_size;
        if total_size <= max_size {
            self.fragment = 0;
            self.flags |= 0x80; // EndOfMessage
            return vec![self];
        }
        let mut fragments = Vec::new();
        let mut current_fragment = CMDU {
            message_version: self.message_version,
            reserved: self.reserved,
            message_type: self.message_type,
            message_id: self.message_id,
            fragment: 0,
            flags: 0,
            payload: Vec::new(),
        };

        let mut current_size = 8; // CMDU header

        for tlv in self.payload.drain(..) {
            let tlv_bytes = tlv.serialize();
            let tlv_len = tlv_bytes.len();

            assert!(
                tlv_len + 8 <= 1500,
                "TLV too large ({}) to fit in the frame of 1500 bytes (TLV max is: {})",
                tlv_len,
                1500 - 8
            );

            if current_size + tlv_len > max_size {
                fragments.push(current_fragment);

                current_fragment = CMDU {
                    message_version: self.message_version,
                    reserved: self.reserved,
                    message_type: self.message_type,
                    message_id: self.message_id,
                    fragment: fragments.len() as u8,
                    flags: 0,
                    payload: Vec::new(),
                };

                current_size = 8;
            }

            current_fragment.payload.push(tlv);
            current_size += tlv_len;
        }

        current_fragment.flags |= 0x80; // End of message flag
        fragments.push(current_fragment);

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
        let last = fragments.last().unwrap();
        if last.flags & 0x80 == 0 {
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
        #[cfg(feature = "size_based_fragmentation")]
        let payload_size = self.payload.len();
        #[cfg(not(feature = "size_based_fragmentation"))]
        let payload_size: usize = self
            .payload
            .iter()
            .map(|tlv| 1 + 2 + tlv.tlv_length as usize) // 1 byte type + 2 bytes length + tlv_length
            .sum();

        header_size + payload_size
    }
}
#[cfg(test)]
pub mod tests {
    use super::*;
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

        #[cfg(feature = "size_based_fragmentation")]
        let mut serialized_payload: Vec<u8> = vec![];
        #[cfg(feature = "size_based_fragmentation")]
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
            #[cfg(feature = "size_based_fragmentation")]
            payload: serialized_payload,
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload,
        }
    }
    #[test]
    fn test_ieee1905_neighbor_device_parse_and_serialize() {
        let local_mac = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);

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
    fn test_vendor_specific_info_parse_invalid_length() {
        // Only 2 bytes of OUI provided (invalid)
        let input = vec![0x01, 0x02];
        let input_length = input.len() as u16;

        let result = VendorSpecificInfo::parse(&input, input_length);
        assert!(
            result.is_err(),
            "Expected parsing to fail due to insufficient length"
        );
    }

    #[test]
    fn test_check_fragmented_cmdu() {
        let end_of_message_tlv = TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        #[cfg(feature = "size_based_fragmentation")]
        let whole_payload = end_of_message_tlv.serialize();
        #[cfg(not(feature = "size_based_fragmentation"))]
        let whole_payload = vec![end_of_message_tlv];

        let cmdu = CMDU {
            message_version: 0x01,
            reserved: 0x00,
            message_type: CMDUType::Unknown(0x08).to_u16(),
            message_id: 0x1234,
            fragment: 0x01,
            flags: 0x00,
            payload: whole_payload
        };
        assert!(cmdu.is_fragmented());
    }

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
        #[cfg(feature = "size_based_fragmentation")]
        let mut serialized_payload: Vec<u8> = vec![];
        #[cfg(feature = "size_based_fragmentation")]
        {
            serialized_payload.extend(al_mac_tlv.clone().serialize());
            serialized_payload.extend(end_of_message_tlv.clone().serialize());
        }
        // Construct the CMDU
        let cmdu_topology_discovery = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::TopologyDiscovery.to_u16(),
            message_id: 123,
            fragment: 0,
            flags: 0x80, // Not fragmented
            #[cfg(feature = "size_based_fragmentation")]
            payload: serialized_payload,
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload: vec![al_mac_tlv.clone(), end_of_message_tlv.clone()],
        };

        // Serialize the CMDU
        let serialized_discovery = cmdu_topology_discovery.serialize();

        // Parse the serialized CMDU
        let parsed_discovery = CMDU::parse(&serialized_discovery).unwrap().1;

        // Assert that the parsed CMDU matches the original
        assert_eq!(cmdu_topology_discovery, parsed_discovery);
    }

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
        #[cfg(feature = "size_based_fragmentation")]
        let mut serialized_payload: Vec<u8> = vec![];
        #[cfg(feature = "size_based_fragmentation")]
        {
            serialized_payload.extend(al_mac_tlv.clone().serialize());
            serialized_payload.extend(end_of_message_tlv.clone().serialize());
        }

        let cmdu_topology_notification = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::TopologyNotification.to_u16(),
            message_id: 456,
            fragment: 0,
            flags: 0x80, // Not fragmented
            #[cfg(feature = "size_based_fragmentation")]
            payload: serialized_payload,
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload: vec![al_mac_tlv.clone(), end_of_message_tlv.clone()],
        };

        let serialized_notification = cmdu_topology_notification.serialize();
        let parsed_notification = CMDU::parse(&serialized_notification).unwrap().1;

        assert_eq!(cmdu_topology_notification, parsed_notification);
    }

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
            flags: 0x80, // Not fragmented
            #[cfg(feature = "size_based_fragmentation")]
            payload: end_of_message_tlv.clone().serialize(),
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload: vec![end_of_message_tlv.clone()],
        };

        let serialized_query = cmdu_topology_query.serialize();
        let parsed_query = CMDU::parse(&serialized_query).unwrap().1;

        assert_eq!(cmdu_topology_query, parsed_query);
    }

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

        #[cfg(feature = "size_based_fragmentation")]
        let mut serialized_payload: Vec<u8> = vec![];
        #[cfg(feature = "size_based_fragmentation")]
        {
            serialized_payload.extend(al_mac_tlv.clone().serialize());
            serialized_payload.extend(mac_address_tlv.clone().serialize());
            serialized_payload.extend(ieee_neighbor_device_tlv.clone().serialize()); // IEEE 1905 Neighbor Devices TLV
            serialized_payload.extend(non_ieee_neighbor_device_tlv.clone().serialize()); // Non-IEEE 1905 Neighbor Devices TLV
            serialized_payload.extend(end_of_message_tlv.clone().serialize());
        }

        let cmdu_topology_response = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::TopologyResponse.to_u16(),
            message_id: 123,
            fragment: 0,
            flags: 0x80, // Not fragmented
            #[cfg(feature = "size_based_fragmentation")]
            payload: serialized_payload,
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload: vec![
                al_mac_tlv.clone(),
                mac_address_tlv.clone(),
                ieee_neighbor_device_tlv.clone(), // IEEE 1905 Neighbor Devices TLV
                non_ieee_neighbor_device_tlv.clone(), // Non-IEEE 1905 Neighbor Devices TLV
                end_of_message_tlv.clone(),
            ],
        };

        let serialized_response = cmdu_topology_response.serialize();
        let parsed_response = CMDU::parse(&serialized_response).unwrap().1;

        assert_eq!(cmdu_topology_response, parsed_response);
    }

    #[test]
    fn test_ap_autoconfig_search_cmdus() {
        // Creation of the TLV searched roe
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

        #[cfg(feature = "size_based_fragmentation")]
        let mut serialized_payload: Vec<u8> = vec![];
        #[cfg(feature = "size_based_fragmentation")]
        {
            serialized_payload.extend(searched_role_tlv.clone().serialize());
            serialized_payload.extend(end_of_message_tlv.clone().serialize());
        }

        // we build the CMDU
        let cmdu_autoconfig_search = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::ApAutoConfigSearch.to_u16(),
            message_id: 42,
            fragment: 0,
            flags: 0x80, // Not fragmented
            #[cfg(feature = "size_based_fragmentation")]
            payload: serialized_payload,
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload: vec![searched_role_tlv.clone(), end_of_message_tlv.clone()],
        };

        // Serializing
        let serialized_cmdus = cmdu_autoconfig_search.serialize();
        let parsed_cmdus = CMDU::parse(&serialized_cmdus).unwrap().1;

        // Verification
        assert_eq!(cmdu_autoconfig_search, parsed_cmdus);
    }

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

        #[cfg(feature = "size_based_fragmentation")]
        let mut serialized_payload: Vec<u8> = vec![];
        #[cfg(feature = "size_based_fragmentation")]
        {
            serialized_payload.extend(supported_role_tlv.clone().serialize());
            serialized_payload.extend(end_of_message_tlv.clone().serialize());
        }
        // we build ApAutoConfigResponse
        let cmdu_autoconfig_response = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::ApAutoConfigResponse.to_u16(),
            message_id: 99,
            fragment: 0,
            flags: 0x80, // Not fragmented
            #[cfg(feature = "size_based_fragmentation")]
            payload: serialized_payload,
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload: vec![supported_role_tlv.clone(), end_of_message_tlv.clone()],
        };

        // serialization and parsing
        let serialized_cmdus = cmdu_autoconfig_response.serialize();
        let parsed_cmdus = CMDU::parse(&serialized_cmdus).unwrap().1;

        // Verification
        assert_eq!(cmdu_autoconfig_response, parsed_cmdus);
    }

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
        #[cfg(feature = "size_based_fragmentation")]
        let mut serialized_payload: Vec<u8> = vec![];
        #[cfg(feature = "size_based_fragmentation")]
        {
            serialized_payload.extend(searched_role_tlv.clone().serialize());
            serialized_payload.extend(end_of_message_tlv.clone().serialize());
        }
        let cmdu = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::ApAutoConfigSearch.to_u16(),
            message_id: 43,
            fragment: 0,
            flags: 0x80,
            #[cfg(feature = "size_based_fragmentation")]
            payload: serialized_payload,
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload: vec![searched_role_tlv.clone(), end_of_message_tlv.clone()],
        };

        let serialized = cmdu.serialize();
        let parsed = CMDU::parse(&serialized).unwrap().1;

        let tlvs = parsed.get_tlvs();
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
        #[cfg(feature = "size_based_fragmentation")]
        let mut serialized_payload: Vec<u8> = vec![];
        #[cfg(feature = "size_based_fragmentation")]
        {
            serialized_payload.extend(searched_role_tlv.clone().serialize());
            serialized_payload.extend(end_of_message_tlv.clone().serialize());
        }
        let cmdu = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: CMDUType::ApAutoConfigSearch.to_u16(),
            message_id: 43,
            fragment: 0,
            flags: 0x80,
            #[cfg(feature = "size_based_fragmentation")]
            payload: serialized_payload,
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload: vec![searched_role_tlv.clone(), end_of_message_tlv.clone()],
        };

        let serialized = cmdu.serialize();
        let parsed = CMDU::parse(&serialized).unwrap().1;

        let tlvs = parsed.get_tlvs();
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

    //TODO reogrginize unit test
    #[test]
    fn test_supported_role_invalid_role() {
        let role = SupportedRole { role: 0x01 };
        let serialized = role.serialize();
        let parsed = SupportedRole::parse(&serialized[..], serialized.len() as u16);

        match parsed {
            Err(nom::Err::Failure(e)) => assert_eq!(e.code, ErrorKind::Verify),
            Ok(_) => panic!(
                "Expected failure due to invalid role value (not 0x00), but parsing succeeded."
            ),
            Err(e) => panic!("Expected Failure(Verify), but got different error: {:?}", e),
        }
    }

    #[test]
    fn test_supported_role_parse_and_serialize() {
        let role = SupportedRole { role: 0x00 };
        let serialized = role.serialize();
        //        let parsed = SupportedRole::parse(&serialized.clone()[..], serialized.len() as u16);
        let parsed = SupportedRole::parse(&serialized[..], serialized.len() as u16);

        assert_eq!(role, parsed.unwrap().1);
    }

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

        #[cfg(feature = "size_based_fragmentation")]
        let mut serialized_payload: Vec<u8> = vec![];
        #[cfg(feature = "size_based_fragmentation")]
        {
            for tlv in unknown_tlvs {
                serialized_payload.extend(tlv.serialize());
            }
            serialized_payload.extend(end_of_message_tlv.clone().serialize());
        }

        #[cfg(not(feature = "size_based_fragmentation"))]
        let whole_payload = unknown_tlvs
            .into_iter()
            .chain(std::iter::once(end_of_message_tlv.clone()))
            .collect();

        let cmdu_unknown = CMDU {
            message_version: 1,
            reserved: 0,
            message_type: 0xFFFF, // Unknown CMDUType
            message_id: 999,
            fragment: 0,
            flags: 0x80, // Not fragmented
            #[cfg(feature = "size_based_fragmentation")]
            payload: serialized_payload,
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload: whole_payload,
        };

        let serialized_unknown = cmdu_unknown.serialize();
        let parsed_unknown = CMDU::parse(&serialized_unknown).unwrap().1;

        assert_eq!(cmdu_unknown, parsed_unknown);
    }

    
    //TODO review the unit test
    #[cfg(not(feature = "size_based_fragmentation"))]
    #[test]
    #[should_panic]
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
            #[cfg(feature = "size_based_fragmentation")]
            payload: end_of_message_tlv.clone().serialize(),
            #[cfg(not(feature = "size_based_fragmentation"))]
            payload: vec![end_of_message_tlv.clone()],
        };

        let serialized_query = cmdu_topology_query.serialize();
        let parsed_query = CMDU::parse(&serialized_query).unwrap().1;

        //#[cfg(not(feature = "size_based_fragmentation"))]
        assert_eq!(cmdu_topology_query, parsed_query);
    }

    //TODO check the unit test
    #[test]
    fn test_fragmentation_and_reassembly() {
        // TLVs that will force at least 2 fragments (each ~600 bytes)
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

    #[test]
    fn test_fragment_no_fragmentation() {
        // Small CMDU that fits in one fragment
        let cmdu = make_dummy_cmdu(vec![100, 200, 300]); // ~600 bytes

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
        assert_eq!(reassembled.payload, cmdu.payload);
    }

    #[test]
    fn test_fragmentation_check_fragments_size() {
        let cmdu = make_dummy_cmdu(vec![1500 - 8 - 3, 500, 900, 1500 - 8 - 3]);

        // Fragment CMDU
        let fragments = cmdu.clone().fragment(1500);
        assert!(fragments.len() >= 3, "Should create at least 3 fragments");

        // Check size of every fragment. Every CMDU fragment (including CMDU header) should have length in range of 11..1500 bytes
        for (i, frag) in fragments.iter().enumerate() {
            assert!(frag.total_size() >= 8 + 3, "Empty CMDU payload in fragment {0}. Fragment {0} should be at least 8+3 bytes (CMDU header + endOfMessageTlv) but is {1} bytes long",
                i, frag.total_size());
            assert!(
                frag.total_size() <= 1500,
                "Fragment {} should have maximum 1500 bytes but is {} bytes long",
                i,
                frag.total_size()
            );
        }

        assert_eq!(cmdu.total_size(), cmdu.serialize().len());
    }

    #[test]
    fn test_total_size() {
        // Small CMDU that fits in one fragment
        let cmdu = make_dummy_cmdu(vec![100, 200, 300]); // ~600 bytes

        assert_eq!(cmdu.total_size(), cmdu.serialize().len());
    }

    #[test]
    #[should_panic]
    #[cfg(
        not(feature = "size_based_fragmentation")
    )] // size based fragmentation allows for a larger payloads
    fn test_a_few_fragments_with_last_one_exceeding_mtu() {
        // CMDU with one TLV exceeding MTU
        let cmdu = make_dummy_cmdu(vec![400, 500, 1500]); // ~2400 bytes

        // Try to do the fragmentation on CMDU
        // It should panic in fragment() as the third TLV (1500B) exceeds maximum allowed size: (MTU - CMDU_header - TLV_header)
        let _fragments = cmdu.clone().fragment(1500);
    }

    #[test]
    fn test_single_cmdu_fragment_with_exact_size_of_mtu() {
        // Single CMDU that fits exactly in one fragment
        let cmdu = make_dummy_cmdu(vec![1500 - 8 - 3]); // Whole CMDU (with CMDU header) has 1500 bytes

        // Do the fragmentation on CMDU
        let fragments = cmdu.clone().fragment(1500);
        assert!(fragments.len() == 1, "Should create exactly 1 fragment");

        for (i, frag) in fragments.iter().enumerate() {
            assert!(frag.total_size() >= 8 + 3, "Empty CMDU payload in fragment {0}. Fragment {0} should be at least 8+3 bytes (CMDU header + endOfMessageTlv) but is {1} bytes long",
                i, frag.total_size());
            assert!(
                frag.total_size() <= 1500,
                "Fragment {} should have maximum 1500 bytes but is {} bytes long",
                i,
                frag.total_size()
            );
        }

        assert_eq!(cmdu.total_size(), cmdu.serialize().len());
    }

    #[test]
    #[cfg(not(feature = "size_based_fragmentation"))]
    fn test_single_cmdu_fragment_without_tlv() {
        // Make CMDU with empty TLV list
        let cmdu = make_dummy_cmdu(vec![]);

        let serialized = cmdu.serialize();
        let z = CMDU::parse(&serialized);

        match z {
            Ok(_) => { panic!("ErrorKind::Eof should be returned"); }
            Err(NomErr::Failure(err)) => {
                assert_eq!(err.code, ErrorKind::Eof);
            }
            Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => panic!("ErrorKind::Eof should be returned")
        }
    }

    #[test]
    #[should_panic]
    #[cfg(not(feature = "size_based_fragmentation"))]
    fn test_single_cmdu_fragment_with_size_of_mtu_plus_one() {
        // Single CMDU that exceeds MTU (1500 bytes) by one byte
        let cmdu = make_dummy_cmdu(vec![1500 - 8 - 3 + 1]); // Whole CMDU (with CMDU header) has 1501 bytes

        // Try to do the fragmentation on CMDU
        // It should panic in fragment() as the TLV (1501B) exceeds maximum allowed size: (MTU - CMDU_header - TLV_header)
        let _fragments = cmdu.clone().fragment(1500);
    }

    #[test]
    fn test_message_version_change() {
        let mut cmd = CMDU {
            message_version: MessageVersion::Version2013.to_u8(),
            reserved: 0,
            message_type: 0x0001,
            message_id: 42,
            fragment: 0,
            flags: 0x80,
            payload: vec![],
        };

        assert_eq!(cmd.message_version, 0x00);

        cmd.set_message_version(MessageVersion::Version2020);

        assert_eq!(cmd.message_version, 0x02);
    }

    #[test]
    fn test_empty_fragment_list() {
        let fragments: Vec<CMDU> = Vec::new();

        // Trying to reassemble empty fragment should cause panic
        let reassembled = CMDU::reassemble(fragments).expect_err("Reassembly shouldn't succeed on empty fragment list");

        assert_eq!(reassembled, CmduReassemblyError::EmptyFragments);
    }

    #[test]
    fn test_inconsistent_data() {
        let cmdu1 = make_dummy_cmdu(vec![100, 200, 300]);
        let mut cmdu2 = make_dummy_cmdu(vec![400, 500, 600]);

        // Override message_id with a value different than default 0x1234
        cmdu2.message_id = 0x6789;

        let fragments: Vec<CMDU> = vec![cmdu1, cmdu2];
        let reassembled = CMDU::reassemble(fragments).expect_err("Reassembly shouldn't succeed on inconsistent CMDUs");

        assert_eq!(reassembled, CmduReassemblyError::InconsistentMetadata);
    }

    #[test]
    fn test_missing_fragments() {
        let mut cmdu1 = make_dummy_cmdu(vec![100, 200, 300]);
        let mut cmdu2 = make_dummy_cmdu(vec![400, 500, 600]);

        // Override fragment_id with a not consecutive values
        cmdu1.fragment = 0x0;
        cmdu2.fragment = 0x2;

        let fragments: Vec<CMDU> = vec![cmdu1, cmdu2];
        let reassembled = CMDU::reassemble(fragments).expect_err("Reassembly shouldn't succeed on missed fragment");

        assert_eq!(reassembled, CmduReassemblyError::MissingFragments);
    }

    #[test]
    fn test_missing_end_of_message() {
        let mut cmdu1 = make_dummy_cmdu(vec![100, 200, 300]);
        let mut cmdu2 = make_dummy_cmdu(vec![400, 500, 600]);

        // Override fragment_id with consecutive values
        cmdu1.fragment = 0x0;
        cmdu2.fragment = 0x1;

        let fragments: Vec<CMDU> = vec![cmdu1, cmdu2];
        let reassembled = CMDU::reassemble(fragments).expect_err("Reassembly shouldn't succeed on missed EndOfMessage TLV");

        assert_eq!(reassembled, CmduReassemblyError::MissingLastFragment);
    }

    #[test]
    fn test_local_interface_parse_and_serialize() {
        let data = &[0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02, 0x00, 0x01, 0x00];
        let local_interface = LocalInterface::parse(data).unwrap();
        assert_eq!(local_interface.1.serialize(), data);

        // Subtest using LocalInterface::new()
        let mac: MacAddr = MacAddr(0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02);
        // Ethernet type
        let media_type: u16 = 0x01;
        let special_info: Vec<u8> = vec![];
        let local_interface = LocalInterface::new(mac, media_type, special_info);
        assert_eq!(local_interface.serialize(), data);
    }

    #[test]
    fn test_local_interface_parse_too_small_data() {
        let data = &[1, 2, 3, 4, 5, 6, 7];
        match LocalInterface::parse(data) {
            Err(NomErr::Failure(err)) => {
                assert_eq!(err.code, ErrorKind::Eof)
            }
            Ok(_) | Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => {
                panic!("ErrorKind::Eof should be returned");
            }
        }
    }

    #[test]
    fn test_device_information_parse_and_serialize() {
        // Mac address, ethernet (0x00, 0x01) as media type and 0x00 as special info
        let data = &[0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02, 0x00, 0x01, 0x00];
        let local_interface = LocalInterface::parse(data).unwrap();
        let mac = MacAddr::new(0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02);
        let device_information = DeviceInformation::new(mac, vec![local_interface.1]);

        let serialized = device_information.serialize();
        let len = serialized.len() as u16;

        match DeviceInformation::parse(&serialized, len) {
            Ok((_, parsed)) => {
                assert_eq!(serialized, parsed.serialize());
            },
            Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) | Err(NomErr::Failure(_)) => {
                panic!("Parsing of serialized data should succeed");
            }
        }
    }

    #[test]
    fn test_device_information_try_to_parse_too_many_data() {
        let mut local_interface_data: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02, 0x00, 0x01, 0x00];
        let mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let mut device_information_data: Vec<u8> = mac;
        device_information_data.push(0x1);
        device_information_data.append(&mut local_interface_data);
        // Add redundant, not needed byte 0xff
        device_information_data.push(0xff);

        let len = device_information_data.len() as u16;

        match DeviceInformation::parse(device_information_data.as_slice(), len) {
            Err(NomErr::Failure(err)) => {
                assert_eq!(err.code, ErrorKind::LengthValue);
            }
            Ok((_, parsed)) => {
                assert_eq!(device_information_data, parsed.serialize());
            }
            Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => panic!("Failure::LengthValue should be returned")
        };
    }

    #[test]
    fn test_bridging_tuple_parse_and_serialize() {
        // 0x01 as number of MAC addresses and MAC address values
        let data = &[0x01, 0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let bridging_tuple = BridgingTuple::parse(data).unwrap();
        let serialized = bridging_tuple.1.serialize();

        match BridgingTuple::parse(&serialized) {
            Ok((_, parsed)) => {
                assert_eq!(serialized, parsed.serialize());
            }

            Err(nom::Err::Incomplete(_)) | Err(NomErr::Failure(_)) | Err(nom::Err::Error(_)) =>
                panic!("Parsing of serialized data should succeed"),
        };
    }

    #[test]
    fn test_bridging_tuple_not_enough_data() {
        // One MAC address counter and MAC address trimmed to 5 bytes
        let data = &[0x01, 0x02, 0x42, 0xc0, 0xa8, 0x64];

        let bridging_tuple = BridgingTuple::parse(data);
        println!("{:?}", bridging_tuple);
        match bridging_tuple {
            Ok(_) => { panic!("ErrorKind::Eof should be returned"); }
            Err(NomErr::Failure(err)) => {
                assert_eq!(err.code, ErrorKind::Eof);
            }
            Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => panic!("ErrorKind::Eof should be returned")
        }
    }

    #[test]
    fn test_device_bridging_capability_parse_and_serialize() {
        let bridging_tuple_data = &[0x01, 0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let bridging_tuple = BridgingTuple::parse(bridging_tuple_data).unwrap();
        let serialized = bridging_tuple.1.serialize();
        // Number of bridging tuples (0x01)
        let mut bridging_capability: Vec<u8> = vec![0x01];

        bridging_capability.append(&mut serialized.clone());

        let parsed = DeviceBridgingCapability::parse(&bridging_capability).unwrap().1;
        assert_eq!(parsed.serialize(), bridging_capability);
    }

    #[test]
    fn test_non_ieee1905_neighbor_parse_and_serialize() {
        let mac = &[0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let parsed = NonIEEE1905Neighbor::parse(mac).unwrap().1;
        assert_eq!(parsed.serialize(), mac);
    }

    #[test]
    fn test_non_ieee1905_local_interface_neighborhood_parse_and_serialize() {
        let al_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        //let parsed = NonIEEE1905Neighbor::parse(mac).unwrap().1;

        let neighbor_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x03];
        let mut neighborhood = al_mac;
        neighborhood.append(&mut neighbor_mac.clone());

        let parsed = NonIEEE1905LocalInterfaceNeighborhood::parse(&neighborhood[..], 1).unwrap().1;
        assert_eq!(parsed.serialize(), neighborhood);
    }

    #[test]
    fn test_non_ieee1905_neighbor_devices_parse_and_serialize() {
        let al_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let neighbor_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x03];

        let mut neighbor_devices: Vec<u8> = al_mac;
        neighbor_devices.append(&mut neighbor_mac.clone());
        let parsed = NonIeee1905NeighborDevices::parse(&neighbor_devices, 1).unwrap().1;
        assert_eq!(parsed.serialize(), neighbor_devices);
    }

    #[test]
    fn test_non_ieee1905_neighbor_devices_not_enough_data_5_bytes() {
        let al_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64];
        let neighbor_devices: Vec<u8> = al_mac;
        let parsed = NonIeee1905NeighborDevices::parse(&neighbor_devices, 1);
        match parsed {
            Ok(_) => { panic!("ErrorKind::Eof should be returned"); }
            Err(NomErr::Error(err)) => {
                println!("errcode___: {:?}", err.code);
                assert_eq!(err.code, ErrorKind::Eof)
            }
            Err(nom::Err::Incomplete(_)) | Err(nom::Err::Failure(_)) => { panic!("ErrorKind::Eof should be returned"); }
        }
    }

    #[test]
    fn test_non_ieee1905_neighbor_devices_not_enough_data_11_bytes() {
        let al_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let neighbor_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64];

        let mut neighbor_devices: Vec<u8> = al_mac;
        neighbor_devices.append(&mut neighbor_mac.clone());

        let parsed = NonIeee1905NeighborDevices::parse(&neighbor_devices, 1);
        match parsed {
            Ok(_) => { panic!("ErrorKind::Eof should be returned"); }
            Err(NomErr::Error(err)) => {
                assert_eq!(err.code, ErrorKind::Eof)
            }
            Err(nom::Err::Incomplete(_)) | Err(nom::Err::Failure(_)) => { panic!("ErrorKind::Eof should be returned"); }
        }
    }

    #[test]
    fn test_al_mac_address_parse_and_serialize() {
        let al_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let parsed = AlMacAddress::parse(&al_mac[..], al_mac.len() as u16).unwrap().1;
        assert_eq!(parsed.serialize(), al_mac);
    }

    #[test]
    #[should_panic]
    fn test_al_mac_address_try_to_parse_not_enough_data() {
        let al_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64];
        let _ = AlMacAddress::parse(&al_mac[..], al_mac.len() as u16).unwrap().1;
    }

    #[test]
    fn test_al_mac_address_try_to_parse_too_much_data() {
        // One redundant byte 0x11 after the MAC address
        let al_mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let mut data: Vec<u8> = al_mac.clone();
        // Add redundant byte which should be returned by parser as unparsed
        data.push(0x11);

        let (rest, _) = AlMacAddress::parse(&data[..], al_mac.len() as u16).unwrap();
        assert_eq!(rest, &[0x11]);
    }


    #[test]
    fn test_mac_address_parse_and_serialize() {
        let mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let parsed = MacAddress::parse(&mac[..], mac.len() as u16).unwrap().1;
        assert_eq!(parsed.serialize(), mac);
    }

    #[test]
    #[should_panic]
    fn test_mac_address_try_to_parse_not_enough_data() {
        let mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64];
        let _ = MacAddress::parse(&mac[..], mac.len() as u16).unwrap().1;
    }

    #[test]
    fn test_mac_address_try_to_parse_too_much_data() {
        // One redundant byte 0x11 after the MAC address
        let mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let mut data: Vec<u8> = mac.clone();
        // Add redundant byte which should be returned by parser as unparsed
        data.push(0x11);
        let (rest, _) = MacAddress::parse(&data[..], mac.len() as u16).unwrap();
        assert_eq!(rest, &[0x11]);
    }

    #[test]
    fn test_message_version_check_version_correctness() {
        assert_eq!(MessageVersion::Version2013.to_u8(), MessageVersion::from_u8(0).unwrap().to_u8());
        assert_eq!(MessageVersion::Version2014.to_u8(), MessageVersion::from_u8(1).unwrap().to_u8());
        assert_eq!(MessageVersion::Version2020.to_u8(), MessageVersion::from_u8(2).unwrap().to_u8());
        assert_eq!(MessageVersion::Version2025.to_u8(), MessageVersion::from_u8(3).unwrap().to_u8());
        assert_eq!(None, MessageVersion::from_u8(4));
    }

    #[test]
    fn test_cmdu_type_check_from_u16() {
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

    #[test]
    fn test_cmdu_type_get_message_version() {
        let cmdu = make_dummy_cmdu(vec![100]);
        assert_eq!(cmdu.get_message_version(), MessageVersion::from_u8(1));
    }

    #[test]
    fn test_cmdu_type_check_to_u16() {
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

    #[test]
    fn test_ieee1905_tlv_type_check_from_u8() {
        assert_eq!(IEEE1905TLVType::from_u8(0x00), IEEE1905TLVType::EndOfMessage);
        assert_eq!(IEEE1905TLVType::from_u8(0x01), IEEE1905TLVType::AlMacAddress);
        assert_eq!(IEEE1905TLVType::from_u8(0x02), IEEE1905TLVType::MacAddress);
        assert_eq!(IEEE1905TLVType::from_u8(0x03), IEEE1905TLVType::DeviceInformation);
        assert_eq!(IEEE1905TLVType::from_u8(0x04), IEEE1905TLVType::DeviceBridgingCapability);
        assert_eq!(IEEE1905TLVType::from_u8(0x05), IEEE1905TLVType::Unknown(0x05));
        assert_eq!(IEEE1905TLVType::from_u8(0x06), IEEE1905TLVType::NonIeee1905NeighborDevices);
        assert_eq!(IEEE1905TLVType::from_u8(0x07), IEEE1905TLVType::Ieee1905NeighborDevices);
        assert_eq!(IEEE1905TLVType::from_u8(0x0b), IEEE1905TLVType::VendorSpecificInfo);
        assert_eq!(IEEE1905TLVType::from_u8(0x0d), IEEE1905TLVType::SearchedRole);
        assert_eq!(IEEE1905TLVType::from_u8(0x0f), IEEE1905TLVType::SupportedRole);
    }

    #[test]
    fn test_ieee1905_tlv_type_check_to_u8() {
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
    #[test]
    fn test_fragmentation(){
        let mut huge_cmdu = make_dummy_cmdu(vec![500,500,500,500]);
        huge_cmdu.flags = 0x80;
        let fragmented_cmdus = huge_cmdu.fragment(1492);
        let no_of_fragments = fragmented_cmdus.len();
        assert!(no_of_fragments == 2);
        assert!(!fragmented_cmdus.first().unwrap().is_last_fragment());
        assert!(fragmented_cmdus.last().unwrap().is_last_fragment());
    }

    #[test]
    #[should_panic]
    #[cfg(feature = "size_based_fragmentation")]
    fn test_get_tlvs_too_short_data() {
        let cmdu = make_dummy_cmdu(vec![100, 200]);

        // prepare bad TLV with length that doesn't match tlv_length
        let bad_tlv_length = TLV {
            tlv_type: IEEE1905TLVType::VendorSpecificInfo.to_u8(),
            tlv_length: 100,
            tlv_value: Some(vec![1]),
        };
        let cmdu_serialized = cmdu.serialize();
        let mut cmdu_payload_extended = cmdu_serialized.clone();
        cmdu_payload_extended.append(&mut bad_tlv_length.serialize());
        let (_, cmdu_parsed) = CMDU::parse(cmdu_payload_extended.as_slice()).unwrap();

        // Expect panic as the bad_tlv_length.tlv_length doesn't match the real TLV length
        let _tlvs = cmdu_parsed.get_tlvs();
    }


    // Test sequence of CMDU fragments that arrived out of order.
    #[test]
    #[cfg(feature = "size_based_fragmentation")]
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
        #[cfg(feature = "size_based_fragmentation")]
        assert_eq!(reassembled.clone().unwrap().payload.len(), 10 + 20 + 30 + 40 + 50 + 60 + 6 * 3);

        // Verify if the data from out of order CMDUs are in proper order after reassembly.
        let mut offset = 0;

        // Define vector of sizes of consecutive TLVs for verification (from already sorted CMDUs)
        let sizes = vec![10, 20, 30, 40, 50, 60];

        // Iter on all the TLVs and check their size with the predefined vector "sizes"
        for i in sizes.iter() {
            let chunk = &reassembled.clone().unwrap().payload[offset..offset + 3 + i];

            #[cfg(feature = "size_based_fragmentation")]
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
        cmdu2.fragment = 3;         // Skip fragment 2 and set fragment to id = 3
        cmdu3.fragment = 4;

        // Set last fragment flag
        cmdu3.flags = 0x80;

        // Prepare vector with CMDU fragments
        let fragments: Vec<CMDU> = vec![cmdu0, cmdu1, cmdu2, cmdu3];
        let reassembled = CMDU::reassemble(fragments);

        // Expect MissingFragments error
        assert_eq!(CmduReassemblyError::MissingFragments, reassembled.unwrap_err());
    }
}
//TODO move everything to size based fragementation and verify all the unit test
//TODO organize the unittest first we verify TLV use cases, content, serialization and parsing, plus error scenarios for malformed