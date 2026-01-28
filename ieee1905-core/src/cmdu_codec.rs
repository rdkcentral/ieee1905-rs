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
use nom::{
    bytes::complete::take,
    error::{Error, ErrorKind},
    number::complete::{be_i8, be_u16, be_u32, be_u8},
    IResult, Parser,
};
use nom::{Err as NomErr, Needed};

use anyhow::bail;
use nom::combinator::{all_consuming, cond};
use nom::multi::{count, many0};
use pnet::datalink::MacAddr;
use std::fmt::{Debug, Display, Formatter};
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
    ApAutoConfigWCS,
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
            0x0009 => CMDUType::ApAutoConfigWCS,
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
            CMDUType::ApAutoConfigWCS => 0x0009,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MultiApProfile {
    Profile1,     // 0x01
    Profile2,     // 0x02
    Profile3,     // 0x03
    Reserved(u8), // 0x04..=0xFF
}
impl MultiApProfile {
    pub fn to_u8(self) -> u8 {
        match self {
            MultiApProfile::Profile1 => 0x01,
            MultiApProfile::Profile2 => 0x02,
            MultiApProfile::Profile3 => 0x03,
            MultiApProfile::Reserved(v) => v,
        }
    }
    pub fn from_u8(v: u8) -> Result<Self, ()> {
        Ok(match v {
            0x01 => MultiApProfile::Profile1,
            0x02 => MultiApProfile::Profile2,
            0x03 => MultiApProfile::Profile3,
            0x04..=0xFF => MultiApProfile::Reserved(v),
            _ => return Err(()), // 0x00 is invalid for Multi-AP Profile
        })
    }
}

///////////////////////////////////////////////////////////////////////////
//Comcast selector
///////////////////////////////////////////////////////////////////////////
pub const COMCAST_OUI: [u8; 3] = [0xD8, 0x9C, 0x8E];
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
    LinkMetricQuery,
    LinkMetricTx,
    LinkMetricRx,
    VendorSpecificInfo,
    LinkMetricResultCode,
    SearchedRole,
    SupportedRole,
    ClientAssociation,
    MultiApProfile,
    Profile2ApCapability,
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
            0x08 => IEEE1905TLVType::LinkMetricQuery,
            0x09 => IEEE1905TLVType::LinkMetricTx,
            0x0a => IEEE1905TLVType::LinkMetricRx,
            0x0b => IEEE1905TLVType::VendorSpecificInfo,
            0x0c => IEEE1905TLVType::LinkMetricResultCode,
            0x0d => IEEE1905TLVType::SearchedRole,
            0x0f => IEEE1905TLVType::SupportedRole,
            0x92 => IEEE1905TLVType::ClientAssociation,
            0xb3 => IEEE1905TLVType::MultiApProfile,
            0xb4 => IEEE1905TLVType::Profile2ApCapability,
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
            IEEE1905TLVType::LinkMetricQuery => 0x08,
            IEEE1905TLVType::LinkMetricTx => 0x09,
            IEEE1905TLVType::LinkMetricRx => 0x0a,
            IEEE1905TLVType::VendorSpecificInfo => 0x0b,
            IEEE1905TLVType::LinkMetricResultCode => 0x0c,
            IEEE1905TLVType::SearchedRole => 0x0d,
            IEEE1905TLVType::SupportedRole => 0x0f,
            IEEE1905TLVType::ClientAssociation => 0x92,
            IEEE1905TLVType::MultiApProfile => 0xb3,
            IEEE1905TLVType::Profile2ApCapability => 0xb4,
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
    pub media_type: MediaType,
    pub special_info: MediaTypeSpecialInfo,
}

impl LocalInterface {
    pub fn new(
        mac_address: MacAddr,
        media_type: MediaType,
        special_info: MediaTypeSpecialInfo,
    ) -> Self {
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
        bytes.extend(self.media_type.serialize());

        // Serialize special_info: first byte is the length, followed by the content
        let special_info = self.special_info.serialize(self.media_type);
        bytes.push(special_info.len() as u8);
        bytes.extend(special_info);

        bytes
    }

    /// Parses a `LocalInterface` from a byte slice.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        // Parse MAC address (6 bytes)
        let (input, mac_address) = take_mac_addr(input)?;

        // Parse media type (2 bytes)
        let (input, media_type) = MediaType::parse(input)?;

        // Parse special_info
        let (input, special_info_length) = be_u8(input)?;
        let (input, special_info) = take(special_info_length as usize)(input)?;
        let special_info = if special_info.is_empty() {
            MediaTypeSpecialInfo::default()
        } else {
            MediaTypeSpecialInfo::parse(media_type, special_info)?.1
        };

        Ok((
            input,
            LocalInterface {
                mac_address,
                media_type,
                special_info,
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
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
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
        let (input, local_interface_list) =
            all_consuming(count(LocalInterface::parse, local_interface_count as usize))
                .parse(input)?;

        Ok((
            input,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationState {
    LeftBss,
    JoinedBss,
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct ClientAssociation {
    pub sta_mac: MacAddr,
    pub ap_mac: MacAddr,
    pub association_state: AssociationState,
}

impl ClientAssociation {
    pub fn parse(input: &[u8], _input_length: u16) -> IResult<&[u8], Self> {
        let (input, sta_bytes) = take(6usize)(input)?;
        let (input, ap_bytes) = take(6usize)(input)?;
        let (input, assoc_byte) = take(1usize)(input)?;

        let sta_mac = MacAddr::new(
            sta_bytes[0],
            sta_bytes[1],
            sta_bytes[2],
            sta_bytes[3],
            sta_bytes[4],
            sta_bytes[5],
        );
        let ap_mac = MacAddr::new(
            ap_bytes[0],
            ap_bytes[1],
            ap_bytes[2],
            ap_bytes[3],
            ap_bytes[4],
            ap_bytes[5],
        );

        let assoc_bits = assoc_byte[0];

        // Only bit7 may be 1, bits 0–6 must be 0
        if assoc_bits & 0x7F != 0 {
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify)));
        }

        let association_state = if (assoc_bits & 0x80) != 0 {
            AssociationState::JoinedBss
        } else {
            AssociationState::LeftBss
        };

        Ok((
            input,
            Self {
                sta_mac,
                ap_mac,
                association_state,
            },
        ))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(13);
        buf.extend_from_slice(&self.sta_mac.octets());
        buf.extend_from_slice(&self.ap_mac.octets());

        // we need to check with a real client bit7 = 1 → joined, bit7 = 0 → left
        let assoc_byte = match self.association_state {
            AssociationState::LeftBss => 0x00,
            AssociationState::JoinedBss => 0x80,
        };

        buf.push(assoc_byte);
        buf
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct MultiApProfileValue {
    pub profile: MultiApProfile,
}

impl MultiApProfileValue {
    pub fn parse(input: &[u8], _input_length: u16) -> IResult<&[u8], Self> {
        let (rest, bytes) = take(1usize)(input)?;
        let v = bytes[0];

        match MultiApProfile::from_u8(v) {
            Ok(profile) => Ok((rest, Self { profile })),
            Err(_) => Err(nom::Err::Failure(Error::new(rest, ErrorKind::Verify))),
        }
    }

    /// Serialize the value to a single byte.
    pub fn serialize(&self) -> Vec<u8> {
        vec![self.profile.to_u8()]
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct Profile2ApCapability {
    pub max_prioritization_rules: u8,
    pub reserved: u8,
    pub byte_counter_units: ByteCounterUnits,
    pub prioritization: bool,
    pub dpp_onboarding: bool,
    pub traffic_separation: bool,
    pub flags_reserved: u8,
    pub max_vids: u8,
}

impl Profile2ApCapability {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, max_prioritization_rules) = be_u8(input)?;
        let (input, reserved) = be_u8(input)?;
        let (input, flags) = be_u8(input)?;
        let (input, max_vids) = be_u8(input)?;

        let this = Self {
            max_prioritization_rules,
            reserved,
            byte_counter_units: ByteCounterUnits::from_u8(flags >> 6),
            prioritization: ((flags >> 5) & 1) == 1,
            dpp_onboarding: ((flags >> 4) & 1) == 1,
            traffic_separation: ((flags >> 3) & 1) == 1,
            flags_reserved: flags & 0b111,
            max_vids,
        };
        Ok((input, this))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let flags = (self.byte_counter_units.to_u8() << 6)
            | ((self.prioritization as u8) << 5)
            | ((self.dpp_onboarding as u8) << 4)
            | ((self.traffic_separation as u8) << 3)
            | (self.flags_reserved & 0b111);

        let mut vec = Vec::new();
        vec.extend(self.max_prioritization_rules.to_be_bytes());
        vec.extend(self.reserved.to_be_bytes());
        vec.extend(flags.to_be_bytes());
        vec.extend(self.max_vids.to_be_bytes());
        vec
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub enum ByteCounterUnits {
    Bytes,
    KiB,
    MiB,
    Reserved,
}

impl ByteCounterUnits {
    pub fn from_u8(input: u8) -> Self {
        match input {
            0 => Self::Bytes,
            1 => Self::KiB,
            2 => Self::MiB,
            _ => Self::Reserved,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            ByteCounterUnits::Bytes => 0,
            ByteCounterUnits::KiB => 1,
            ByteCounterUnits::MiB => 2,
            ByteCounterUnits::Reserved => 3,
        }
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct LinkMetricQuery {
    pub neighbor_type: u8,
    pub neighbor_mac: Option<MacAddr>,
    pub requested_metrics: u8,
}

impl LinkMetricQuery {
    pub const NEIGHBOR_ALL: u8 = 0x00;
    pub const NEIGHBOR_SPECIFIC: u8 = 0x01;

    pub const METRIC_TX: u8 = 0x00;
    pub const METRIC_RX: u8 = 0x01;
    pub const METRIC_TX_RX: u8 = 0x02;

    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, neighbor_type) = be_u8(input)?;

        let specific_neighbor = neighbor_type == Self::NEIGHBOR_SPECIFIC;
        let (input, neighbor_mac) = cond(specific_neighbor, take_mac_addr).parse(input)?;
        let (input, requested_metrics) = be_u8(input)?;

        Ok((
            input,
            Self {
                neighbor_type,
                neighbor_mac,
                requested_metrics,
            },
        ))
    }

    pub fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        let mut vec = Vec::new();
        vec.push(self.neighbor_type);

        if self.neighbor_type == Self::NEIGHBOR_SPECIFIC {
            if let Some(mac) = self.neighbor_mac {
                vec.extend(mac.octets());
            } else {
                bail!("LinkMetricQuery -> mac is missing when NEIGHBOR_SPECIFIC flag is present");
            }
        }
        vec.push(self.requested_metrics);

        Ok(vec)
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct LinkMetricTx {
    pub source_al_mac: MacAddr,
    pub neighbour_al_mac: MacAddr,
    pub interface_pairs: Vec<LinkMetricTxPair>,
}

impl LinkMetricTx {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, source_al_mac) = take_mac_addr(input)?;
        let (input, neighbour_al_mac) = take_mac_addr(input)?;
        let (input, interface_pairs) =
            all_consuming(many0(LinkMetricTxPair::parse)).parse(input)?;

        Ok((
            input,
            Self {
                source_al_mac,
                neighbour_al_mac,
                interface_pairs,
            },
        ))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend(self.source_al_mac.octets());
        vec.extend(self.neighbour_al_mac.octets());
        for pair in self.interface_pairs.iter() {
            vec.extend(pair.serialize());
        }
        vec
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct LinkMetricTxPair {
    pub receiver_interface_mac: MacAddr,
    pub neighbour_interface_mac: MacAddr,
    pub interface_type: MediaType,
    pub has_more_ieee802_bridges: u8,
    pub packet_errors: u32,
    pub transmitted_packets: u32,
    pub mac_throughput_capacity: u16,
    pub link_availability: u16,
    pub phy_rate: u16,
}

impl LinkMetricTxPair {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, receiver_interface_mac) = take_mac_addr(input)?;
        let (input, neighbour_interface_mac) = take_mac_addr(input)?;
        let (input, interface_type) = MediaType::parse(input)?;
        let (input, has_more_ieee802_bridges) = be_u8(input)?;
        let (input, packet_errors) = be_u32(input)?;
        let (input, transmitted_packets) = be_u32(input)?;
        let (input, mac_throughput_capacity) = be_u16(input)?;
        let (input, link_availability) = be_u16(input)?;
        let (input, phy_rate) = be_u16(input)?;

        Ok((
            input,
            Self {
                receiver_interface_mac,
                neighbour_interface_mac,
                interface_type,
                has_more_ieee802_bridges,
                packet_errors,
                transmitted_packets,
                mac_throughput_capacity,
                link_availability,
                phy_rate,
            },
        ))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend(self.receiver_interface_mac.octets());
        vec.extend(self.neighbour_interface_mac.octets());
        vec.extend(self.interface_type.serialize());
        vec.extend(self.has_more_ieee802_bridges.to_be_bytes());
        vec.extend(self.packet_errors.to_be_bytes());
        vec.extend(self.transmitted_packets.to_be_bytes());
        vec.extend(self.mac_throughput_capacity.to_be_bytes());
        vec.extend(self.link_availability.to_be_bytes());
        vec.extend(self.phy_rate.to_be_bytes());
        vec
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct LinkMetricRx {
    pub source_al_mac: MacAddr,
    pub neighbour_al_mac: MacAddr,
    pub interface_pairs: Vec<LinkMetricRxPair>,
}

impl LinkMetricRx {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, source_al_mac) = take_mac_addr(input)?;
        let (input, neighbour_al_mac) = take_mac_addr(input)?;
        let (input, interface_pairs) =
            all_consuming(many0(LinkMetricRxPair::parse)).parse(input)?;

        Ok((
            input,
            Self {
                source_al_mac,
                neighbour_al_mac,
                interface_pairs,
            },
        ))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend(self.source_al_mac.octets());
        vec.extend(self.neighbour_al_mac.octets());
        for pair in self.interface_pairs.iter() {
            vec.extend(pair.serialize());
        }
        vec
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct LinkMetricRxPair {
    pub receiver_interface_mac: MacAddr,
    pub neighbour_interface_mac: MacAddr,
    pub interface_type: MediaType,
    pub packet_errors: u32,
    pub transmitted_packets: u32,
    pub rssi: i8,
}

impl LinkMetricRxPair {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, receiver_interface_mac) = take_mac_addr(input)?;
        let (input, neighbour_interface_mac) = take_mac_addr(input)?;
        let (input, interface_type) = MediaType::parse(input)?;
        let (input, packet_errors) = be_u32(input)?;
        let (input, transmitted_packets) = be_u32(input)?;
        let (input, rssi) = be_i8(input)?;

        Ok((
            input,
            Self {
                receiver_interface_mac,
                neighbour_interface_mac,
                interface_type,
                packet_errors,
                transmitted_packets,
                rssi,
            },
        ))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend(self.receiver_interface_mac.octets());
        vec.extend(self.neighbour_interface_mac.octets());
        vec.extend(self.interface_type.serialize());
        vec.extend(self.packet_errors.to_be_bytes());
        vec.extend(self.transmitted_packets.to_be_bytes());
        vec.extend(self.rssi.to_be_bytes());
        vec
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub enum LinkMetricResultCode {
    InvalidNeighbor,
    UnknownCode(u8),
}

impl LinkMetricResultCode {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, code) = be_u8(input)?;
        let this = match code {
            0x00 => Self::InvalidNeighbor,
            _ => Self::UnknownCode(code),
        };
        Ok((input, this))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let code = match self {
            Self::InvalidNeighbor => 0x00,
            Self::UnknownCode(e) => *e,
        };

        let mut vec = Vec::new();
        vec.extend(code.to_be_bytes());
        vec
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct MediaType(pub u16);

#[allow(non_upper_case_globals)]
impl MediaType {
    // ethernet
    pub const ETHERNET_802_3u: Self = Self(0x0000);
    pub const ETHERNET_802_3ab: Self = Self(0x0001);
    // wireless
    pub const WIRELESS_802_11b_2_4: Self = Self(0x0100);
    pub const WIRELESS_802_11g_2_4: Self = Self(0x0101);
    pub const WIRELESS_802_11a_5: Self = Self(0x0102);
    pub const WIRELESS_802_11n_2_4: Self = Self(0x0103);
    pub const WIRELESS_802_11n_5: Self = Self(0x0104);
    pub const WIRELESS_802_11ac_5: Self = Self(0x0105);
    pub const WIRELESS_802_11ad_60: Self = Self(0x0106);
    pub const WIRELESS_802_11af: Self = Self(0x0107);
    pub const WIRELESS_802_11ax: Self = Self(0x0108);
    pub const WIRELESS_802_11be: Self = Self(0x0109);
    // IEEE 1901
    pub const IEEE_1901_Wavelet: Self = Self(0x0200);
    pub const IEEE_1901_FFT: Self = Self(0x0201);
    // MoCA
    pub const MoCA_1_1: Self = Self(0x0300);

    pub fn is_ethernet(&self) -> bool {
        (self.0 & 0xff00) == 0x0000
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, value) = be_u16(input)?;
        Ok((input, Self(value)))
    }

    pub fn serialize(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl Debug for MediaType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MediaType({:04X?})", self.0)
    }
}

impl Display for MediaType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let [a, b] = self.0.to_be_bytes();
        match a {
            0 => match b {
                0 => write!(f, "IEEE 802.3u fast Ethernet"),
                1 => write!(f, "IEEE 802.3ab gigabit Ethernet"),
                _ => write!(f, "IEEE 802.3 Unknown({b})"),
            },
            1 => match b {
                0 => write!(f, "IEEE 802.11b (2.4 GHz)"),
                1 => write!(f, "IEEE 802.11g (2.4 GHz)"),
                2 => write!(f, "IEEE 802.11a (5 GHz)"),
                3 => write!(f, "IEEE 802.11n (2.4 GHz)"),
                4 => write!(f, "IEEE 802.11n (5 GHz)"),
                5 => write!(f, "IEEE 802.11ac (5 GHz)"),
                6 => write!(f, "IEEE 802.11ad (60 GHz)"),
                7 => write!(f, "IEEE 802.11af"),
                8 => write!(f, "IEEE 802.11ax"),
                9 => write!(f, "IEEE 802.11be"),
                _ => write!(f, "IEEE 802.11 Unknown({b})"),
            },
            _ => write!(f, "MediaType({b})"),
        }
    }
}

///
/// Media-specific information (IEEE 1905-2013, Table 6-12)
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaTypeSpecialInfo {
    Wifi(MediaTypeSpecialInfoWifi),
    Other(Vec<u8>),
}

impl MediaTypeSpecialInfo {
    pub fn parse(media_type: MediaType, input: &[u8]) -> IResult<&[u8], Self> {
        if (0x0100..0x0108).contains(&media_type.0) {
            // Wifi6 and Wifi7 don't have extras
            let (input, result) = MediaTypeSpecialInfoWifi::parse(input)?;
            return Ok((input, Self::Wifi(result)));
        }
        Ok((&[], Self::Other(input.to_vec())))
    }

    pub fn serialize(&self, media_type: MediaType) -> Vec<u8> {
        if (0x0108..0x01ff).contains(&media_type.0) {
            // Wifi6 and Wifi7 don't have extras
            return Default::default();
        }
        match self {
            MediaTypeSpecialInfo::Wifi(e) => e.serialize(),
            MediaTypeSpecialInfo::Other(e) => e.clone(),
        }
    }
}

impl Default for MediaTypeSpecialInfo {
    fn default() -> Self {
        Self::Other(Default::default())
    }
}

///
/// IEEE 802.11 specific information
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaTypeSpecialInfoWifi {
    pub bssid: MacAddr,
    pub role: u8,
    pub reserved: u8,
    pub ap_channel_band: u8,
    pub ap_channel_center_frequency_index1: u8,
    pub ap_channel_center_frequency_index2: u8,
}

impl MediaTypeSpecialInfoWifi {
    const MASK_ROLE: u8 = 0x0F;
    const MASK_RESERVED: u8 = 0xF0;

    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, bssid) = take_mac_addr(input)?;
        let (input, role_plus) = be_u8(input)?;
        let (input, ap_channel_band) = be_u8(input)?;
        let (input, ap_channel_center_frequency_index1) = be_u8(input)?;
        let (input, ap_channel_center_frequency_index2) = be_u8(input)?;

        Ok((
            input,
            Self {
                bssid,
                role: role_plus & Self::MASK_ROLE,
                reserved: role_plus & Self::MASK_RESERVED,
                ap_channel_band,
                ap_channel_center_frequency_index1,
                ap_channel_center_frequency_index2,
            },
        ))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let role_plus = (self.role & Self::MASK_ROLE) | (self.reserved & Self::MASK_RESERVED);

        let mut vec = Vec::new();
        vec.extend(self.bssid.octets());
        vec.extend(role_plus.to_be_bytes());
        vec.extend(self.ap_channel_band.to_be_bytes());
        vec.extend(self.ap_channel_center_frequency_index1.to_be_bytes());
        vec.extend(self.ap_channel_center_frequency_index2.to_be_bytes());
        vec
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Default, Debug, Copy, Clone)]
pub enum CMDUFragmentation {
    #[default]
    TLVBoundary,
    ByteBoundary,
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
    pub const HEADER_SIZE: usize = 8;
    pub const FLAG_LAST_FRAGMENT: u8 = 0x80;

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

    pub fn fragment(self, kind: CMDUFragmentation, max_size: usize) -> anyhow::Result<Vec<CMDU>> {
        Ok(match kind {
            CMDUFragmentation::TLVBoundary => self.fragment_tlv_boundary(max_size)?,
            CMDUFragmentation::ByteBoundary => self.fragment_byte_boundary(max_size),
        })
    }

    pub fn fragment_tlv_boundary(mut self, max_size: usize) -> anyhow::Result<Vec<CMDU>> {
        let max_content_size = max_size - Self::HEADER_SIZE;
        if self.payload.len() <= max_content_size {
            self.flags |= Self::FLAG_LAST_FRAGMENT;
            return Ok(vec![self]);
        }

        let mut fragments = Vec::<Self>::new();
        for tlv in self.get_tlvs()? {
            let tlv_size = tlv.total_size();
            if tlv_size > max_content_size {
                bail!("TLV is too large, size = {tlv_size}/{max_content_size}");
            }

            if let Some(fragment) = fragments.last_mut() {
                if fragment.payload.len() + tlv_size <= max_content_size {
                    fragment.payload.extend(tlv.serialize());
                    continue;
                }
            }

            fragments.push(Self {
                message_version: self.message_version,
                reserved: self.reserved,
                message_type: self.message_type,
                message_id: self.message_id,
                fragment: fragments.len() as u8,
                flags: self.flags & (!Self::FLAG_LAST_FRAGMENT),
                payload: tlv.serialize(),
            });
        }

        if let Some(fragment) = fragments.last_mut() {
            fragment.flags |= Self::FLAG_LAST_FRAGMENT;
        }
        Ok(fragments)
    }

    pub fn fragment_byte_boundary(mut self, max_size: usize) -> Vec<CMDU> {
        let max_content_size = max_size - Self::HEADER_SIZE;
        if self.payload.len() <= max_content_size {
            self.flags |= Self::FLAG_LAST_FRAGMENT;
            return vec![self];
        }

        let chunks = self.payload.chunks(max_content_size);
        let mut fragments = chunks
            .enumerate()
            .map(|(index, e)| Self {
                message_version: self.message_version,
                reserved: self.reserved,
                message_type: self.message_type,
                message_id: self.message_id,
                fragment: index as u8,
                flags: self.flags & (!Self::FLAG_LAST_FRAGMENT),
                payload: e.to_vec(),
            })
            .collect::<Vec<_>>();

        if let Some(fragment) = fragments.last_mut() {
            fragment.flags |= Self::FLAG_LAST_FRAGMENT;
        }
        fragments
    }

    pub fn reassemble(mut fragments: Vec<CMDU>) -> Result<CMDU, CmduReassemblyError> {
        let Some(fragment0) = fragments.first() else {
            return Err(CmduReassemblyError::EmptyFragments);
        };

        // Check metadata consistency
        let message_version = fragment0.message_version;
        let message_type = fragment0.message_type;
        let message_id = fragment0.message_id;

        if !fragments.iter().all(|f| {
            f.message_version == message_version
                && f.message_type == message_type
                && f.message_id == message_id
        }) {
            return Err(CmduReassemblyError::InconsistentMetadata);
        }

        // Sort by fragment number
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
        self.payload.len() + Self::HEADER_SIZE
    }
}

fn take_n_bytes<const N: usize>(input: &[u8]) -> IResult<&[u8], &[u8; N]> {
    let (input, bytes) = take(N)(input)?;
    match bytes.try_into() {
        Ok(e) => Ok((input, e)),
        Err(_) => Err(nom::Err::Incomplete(Needed::new(N))),
    }
}

fn take_mac_addr(input: &[u8]) -> IResult<&[u8], MacAddr> {
    let (input, bytes) = take_n_bytes::<6>(input)?;
    let mac = MacAddr::from(*bytes);
    Ok((input, mac))
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
            message_version: MessageVersion::Version2013.to_u8(),
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
        assert_eq!(CMDUType::from_u16(9), CMDUType::ApAutoConfigWCS);
    }

    // Verify function for getting message version of CMDU
    #[test]
    fn test_cmdu_type_get_message_version() {
        // Create a dummy CMDU with message_version field set to 0x1
        let cmdu = make_dummy_cmdu(vec![100]);

        // Expect success getting message version of CMDU
        assert_eq!(
            cmdu.get_message_version(),
            Some(MessageVersion::Version2013)
        );
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
        assert_eq!(CMDUType::ApAutoConfigWCS.to_u16(), 9);
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
            IEEE1905TLVType::from_u8(0x08),
            IEEE1905TLVType::LinkMetricQuery,
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x09),
            IEEE1905TLVType::LinkMetricTx,
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x0a),
            IEEE1905TLVType::LinkMetricRx,
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x0b),
            IEEE1905TLVType::VendorSpecificInfo
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x0c),
            IEEE1905TLVType::LinkMetricResultCode,
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x0d),
            IEEE1905TLVType::SearchedRole
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x0f),
            IEEE1905TLVType::SupportedRole
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0x92),
            IEEE1905TLVType::ClientAssociation,
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0xb3),
            IEEE1905TLVType::MultiApProfile,
        );
        assert_eq!(
            IEEE1905TLVType::from_u8(0xb4),
            IEEE1905TLVType::Profile2ApCapability,
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
        assert_eq!(IEEE1905TLVType::LinkMetricQuery.to_u8(), 0x08);
        assert_eq!(IEEE1905TLVType::LinkMetricTx.to_u8(), 0x09);
        assert_eq!(IEEE1905TLVType::LinkMetricRx.to_u8(), 0x0a);
        assert_eq!(IEEE1905TLVType::VendorSpecificInfo.to_u8(), 0x0b);
        assert_eq!(IEEE1905TLVType::LinkMetricResultCode.to_u8(), 0x0c);
        assert_eq!(IEEE1905TLVType::SearchedRole.to_u8(), 0x0d);
        assert_eq!(IEEE1905TLVType::SupportedRole.to_u8(), 0x0f);
        assert_eq!(IEEE1905TLVType::ClientAssociation.to_u8(), 0x92);
        assert_eq!(IEEE1905TLVType::MultiApProfile.to_u8(), 0xb3);
        assert_eq!(IEEE1905TLVType::Profile2ApCapability.to_u8(), 0xb4);
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
        let fragments = cmdu.clone().fragment_tlv_boundary(1500).unwrap();
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

        let fragments = cmdu.clone().fragment_tlv_boundary(1500).unwrap();
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
        let fragments = cmdu.clone().fragment_tlv_boundary(1500).unwrap();
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
        // It should panic as TLV based fragmentation doesn't allow TLV payload bigger than MTU
        let result = cmdu.clone().fragment_tlv_boundary(1500);
        assert!(result.is_err(), "Serializaed TLV bigger than MTU");
    }

    // Verify the correctness of fragmentation and reassembly of CMDU fitting exactly CMDU size
    #[test]
    fn test_single_cmdu_fragment_with_exact_size_of_mtu() {
        // Create single CMDU that fits exactly in one fragment
        let cmdu = make_dummy_cmdu(vec![1500 - 8 - 3]); // Whole CMDU (with CMDU header) has 1500 bytes

        // Do the fragmentation on CMDU
        let fragments = cmdu.clone().fragment_tlv_boundary(1500).unwrap();
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
        let fragmented_cmdus = huge_cmdu.fragment_tlv_boundary(1500).unwrap();

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
            message_version: MessageVersion::Version2013.to_u8(),
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
            message_version: MessageVersion::Version2013.to_u8(),
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
            message_version: MessageVersion::Version2013.to_u8(),
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
            message_version: MessageVersion::Version2013.to_u8(),
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
            message_version: MessageVersion::Version2013.to_u8(),
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
            message_version: MessageVersion::Version2013.to_u8(),
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
            message_version: MessageVersion::Version2013.to_u8(),
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
            message_version: MessageVersion::Version2013.to_u8(),
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
            message_version: MessageVersion::Version2013.to_u8(),
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
        let media_type = MediaType::ETHERNET_802_3ab; // Set ethernet type
        let special_info = MediaTypeSpecialInfo::default(); // Empty "special info" data
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

        // Expect that parsing DeviceInformation data succeed
        match DeviceInformation::parse(&serialized) {
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
            message_version: MessageVersion::Version2013.to_u8(),
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

    #[test]
    fn test_client_association_serialization() {
        let original = ClientAssociation {
            sta_mac: MacAddr::new(1, 2, 3, 4, 5, 6),
            ap_mac: MacAddr::new(6, 5, 4, 3, 2, 1),
            association_state: AssociationState::JoinedBss,
        };

        let bytes = original.serialize();
        assert_eq!(
            bytes,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // sta_mac
                0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // ap_mac
                0x80, // association_state
            ]
        );

        let parsed = ClientAssociation::parse(&bytes, bytes.len() as u16)
            .unwrap()
            .1;
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_multi_ap_profile_value_serialization() {
        let original = MultiApProfileValue {
            profile: MultiApProfile::Profile1,
        };

        let bytes = original.serialize();
        assert_eq!(bytes, [0x01]);

        let parsed = MultiApProfileValue::parse(&bytes, bytes.len() as u16).unwrap();
        assert_eq!(parsed.1, original);
    }

    #[test]
    fn test_profile2ap_capability_serialization() {
        let original = [0x05, 0x00, 0b01100111, 0x10];

        let parsed = Profile2ApCapability::parse(&original).unwrap().1;
        assert_eq!(parsed.max_prioritization_rules, 0x05);
        assert_eq!(parsed.reserved, 0x00);
        assert_eq!(parsed.byte_counter_units, ByteCounterUnits::KiB);
        assert!(parsed.prioritization);
        assert!(!parsed.dpp_onboarding);
        assert!(!parsed.traffic_separation);
        assert_eq!(parsed.flags_reserved, 0b111);

        let serialized = parsed.serialize();
        assert_eq!(original.as_slice(), serialized);
    }

    #[test]
    fn test_byte_counter_units_serialization() {
        assert_eq!(ByteCounterUnits::from_u8(0x00), ByteCounterUnits::Bytes);
        assert_eq!(ByteCounterUnits::from_u8(0x01), ByteCounterUnits::KiB);
        assert_eq!(ByteCounterUnits::from_u8(0x02), ByteCounterUnits::MiB);
        assert_eq!(ByteCounterUnits::from_u8(0x03), ByteCounterUnits::Reserved);
        assert_eq!(ByteCounterUnits::from_u8(0x04), ByteCounterUnits::Reserved);

        assert_eq!(ByteCounterUnits::Bytes.to_u8(), 0x00);
        assert_eq!(ByteCounterUnits::KiB.to_u8(), 0x01);
        assert_eq!(ByteCounterUnits::MiB.to_u8(), 0x02);
        assert_eq!(ByteCounterUnits::Reserved.to_u8(), 0x03);
    }

    #[test]
    fn test_link_metric_query_all_neighbors_serialization() {
        let original = [0x00, 0x02];

        let parsed = LinkMetricQuery::parse(&original).unwrap().1;
        assert_eq!(parsed.neighbor_type, LinkMetricQuery::NEIGHBOR_ALL);
        assert_eq!(parsed.neighbor_mac, None);
        assert_eq!(parsed.requested_metrics, LinkMetricQuery::METRIC_TX_RX);

        let serialized = parsed.serialize().unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn test_link_metric_query_specific_neighbor_serialization() {
        let original = [0x01, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x01];

        let parsed = LinkMetricQuery::parse(&original).unwrap().1;
        assert_eq!(parsed.neighbor_type, LinkMetricQuery::NEIGHBOR_SPECIFIC);
        assert_eq!(
            parsed.neighbor_mac,
            Some(MacAddr::new(0x40, 0x41, 0x42, 0x43, 0x44, 0x45))
        );
        assert_eq!(parsed.requested_metrics, LinkMetricQuery::METRIC_RX);

        let serialized = parsed.serialize().unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn test_link_metric_tx_serialization() {
        let original = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, // source al_mac
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, // neighbour al_mac
            // interface pair 1
            0x60, 0x61, 0x62, 0x63, 0x64, 0x66, // receiver interface mac
            0x70, 0x71, 0x72, 0x73, 0x74, 0x77, // neighbour interface mac
            0x00, 0x01, // interface type
            0x00, // no more bridges
            0x00, 0x00, 0x00, 0x13, // packet errors
            0x00, 0x00, 0x00, 0x42, // transmitted packets
            0x00, 0x80, // mac throughput capacity
            0x00, 0x64, // link availability
            0x00, 0x10, // phy rate
        ];

        let parsed = LinkMetricTx::parse(&original).unwrap().1;
        assert_eq!(
            parsed.source_al_mac,
            MacAddr::new(0x40, 0x41, 0x42, 0x43, 0x44, 0x45)
        );
        assert_eq!(
            parsed.neighbour_al_mac,
            MacAddr::new(0x50, 0x51, 0x52, 0x53, 0x54, 0x55)
        );

        let pair = &parsed.interface_pairs[0];
        assert_eq!(
            pair.receiver_interface_mac,
            MacAddr::new(0x60, 0x61, 0x62, 0x63, 0x64, 0x66)
        );
        assert_eq!(
            pair.neighbour_interface_mac,
            MacAddr::new(0x70, 0x71, 0x72, 0x73, 0x74, 0x77)
        );
        assert_eq!(pair.interface_type, MediaType::ETHERNET_802_3ab);
        assert_eq!(pair.has_more_ieee802_bridges, 0);
        assert_eq!(pair.packet_errors, 0x13);
        assert_eq!(pair.transmitted_packets, 0x42);
        assert_eq!(pair.mac_throughput_capacity, 0x80);
        assert_eq!(pair.link_availability, 0x64);
        assert_eq!(pair.phy_rate, 0x10);

        let serialized = parsed.serialize();
        assert_eq!(serialized, original);
    }

    #[test]
    fn test_link_metric_rx_serialization() {
        let original = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, // source al_mac
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, // neighbour al_mac
            // interface pair 1
            0x60, 0x61, 0x62, 0x63, 0x64, 0x66, // receiver interface mac
            0x70, 0x71, 0x72, 0x73, 0x74, 0x77, // neighbour interface mac
            0x00, 0x01, // interface type
            0x00, 0x00, 0x00, 0x13, // packet errors
            0x00, 0x00, 0x00, 0x42, // transmitted packets
            0x10, // rssi
        ];

        let parsed = LinkMetricRx::parse(&original).unwrap().1;
        assert_eq!(
            parsed.source_al_mac,
            MacAddr::new(0x40, 0x41, 0x42, 0x43, 0x44, 0x45)
        );
        assert_eq!(
            parsed.neighbour_al_mac,
            MacAddr::new(0x50, 0x51, 0x52, 0x53, 0x54, 0x55)
        );

        let pair = &parsed.interface_pairs[0];
        assert_eq!(
            pair.receiver_interface_mac,
            MacAddr::new(0x60, 0x61, 0x62, 0x63, 0x64, 0x66)
        );
        assert_eq!(
            pair.neighbour_interface_mac,
            MacAddr::new(0x70, 0x71, 0x72, 0x73, 0x74, 0x77)
        );
        assert_eq!(pair.interface_type, MediaType::ETHERNET_802_3ab);
        assert_eq!(pair.packet_errors, 0x13);
        assert_eq!(pair.transmitted_packets, 0x42);
        assert_eq!(pair.rssi, 0x10);

        let serialized = parsed.serialize();
        assert_eq!(serialized, original);
    }

    #[test]
    fn test_link_metric_result_code_serialization() {
        let pairs = [
            (0x00, LinkMetricResultCode::InvalidNeighbor),
            (0x01, LinkMetricResultCode::UnknownCode(0x01)),
        ];

        for (code, expected) in pairs {
            let slice = std::slice::from_ref(&code);

            let parsed = LinkMetricResultCode::parse(slice).unwrap().1;
            assert_eq!(parsed, expected);

            let serialized = parsed.serialize();
            assert_eq!(serialized, slice);
        }
    }

    #[test]
    fn test_media_type_special_info_wifi_serialization() {
        let original = [
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, // BSSID
            0x04, // role
            0x00, 0x01, 0x00,
        ];

        let parsed = MediaTypeSpecialInfoWifi::parse(&original).unwrap().1;
        assert_eq!(parsed.bssid.octets(), [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6]);
        assert_eq!(parsed.role, 0x04);
        assert_eq!(parsed.ap_channel_band, 0x00);
        assert_eq!(parsed.ap_channel_center_frequency_index1, 0x01);
        assert_eq!(parsed.ap_channel_center_frequency_index2, 0x00);

        let serialized = parsed.serialize();
        assert_eq!(serialized, original);
    }

    #[test]
    fn test_multi_ap_profile_serialization() {
        assert_eq!(MultiApProfile::Profile1.to_u8(), 0x01);
        assert_eq!(MultiApProfile::Profile2.to_u8(), 0x02);
        assert_eq!(MultiApProfile::Profile3.to_u8(), 0x03);
        assert_eq!(MultiApProfile::Reserved(0x80).to_u8(), 0x80);
    }

    #[test]
    fn test_multi_ap_profile_deserialization() {
        assert_eq!(MultiApProfile::from_u8(0x01), Ok(MultiApProfile::Profile1));
        assert_eq!(MultiApProfile::from_u8(0x02), Ok(MultiApProfile::Profile2));
        assert_eq!(MultiApProfile::from_u8(0x03), Ok(MultiApProfile::Profile3));
        assert_eq!(
            MultiApProfile::from_u8(0x80),
            Ok(MultiApProfile::Reserved(0x80))
        );
        assert_eq!(MultiApProfile::from_u8(0x00), Err(()));
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
            message_version: MessageVersion::Version2013.to_u8(),
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
            Err(NomErr::Error(err)) => {
                assert_eq!(err.input.len(), 1);
                assert_eq!(err.code, ErrorKind::Eof);
            }
            _ => {
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

        // Expect LenghtValue error trying to parse the DeviceInformation data because of one dummy, not needed byte: 0xFF
        match DeviceInformation::parse(device_information_data.as_slice()) {
            Err(NomErr::Error(err)) => {
                assert_eq!(err.input, &[0xff]);
                assert_eq!(err.code, ErrorKind::Eof);
            }
            _ => panic!("Failure::LengthValue should be returned"),
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
        let fragments = cmdu.clone().fragment_byte_boundary(1500);

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
            message_version: MessageVersion::Version2013.to_u8(),
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
