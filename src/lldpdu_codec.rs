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
    error::ErrorKind,
    number::complete::{be_u16, be_u8},
    Err as NomErr, IResult,
};
use pnet::datalink::MacAddr;

// Standard library
use std::fmt::Debug;

// Internal modules
use crate::tlv_lldpdu_codec::TLV;

///////////////////////////////////////////////////////////////////////////
//DEFINITION LLDPDU TLVs
///////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq)]
pub enum LLDPTLVType {
    EndOfLldpdu,
    ChassisId,
    PortId,
    TimeToLive,
    Unknown(u8), // To handle unknown or unsupported TLV types
}

impl LLDPTLVType {
    // Function to convert from u8 to the appropriate LLDPTLVType enum variant
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => LLDPTLVType::EndOfLldpdu,
            0x01 => LLDPTLVType::ChassisId,
            0x02 => LLDPTLVType::PortId,
            0x03 => LLDPTLVType::TimeToLive,
            _ => LLDPTLVType::Unknown(value),
        }
    }

    // Function to convert from LLDPTLVType enum variant back into the corresponding u8 value
    pub fn to_u8(&self) -> u8 {
        match *self {
            LLDPTLVType::EndOfLldpdu => 0x00,
            LLDPTLVType::ChassisId => 0x01,
            LLDPTLVType::PortId => 0x02,
            LLDPTLVType::TimeToLive => 0x03,
            LLDPTLVType::Unknown(value) => value, // For unknown TLV types
        }
    }
}

///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct ChassisId {
    pub chassis_id_type: u8,
    pub chassis_id: MacAddr,
}

impl ChassisId {
    // Parse function for ChassisId
    pub fn parse(input: &[u8], input_length: u16) -> IResult<&[u8], Self> {
        // Parse the chassis_id_type (1 byte)
        let (input, chassis_id_type) = be_u8(input)?;

        // Ensure that the remaining input length is correct for a MAC address (6 bytes)
        if input.len() < input_length as usize - 1 {
            return Err(NomErr::Failure(nom::error::Error::new(
                input,
                ErrorKind::LengthValue,
            )));
        }

        // Parse the chassis_id (6 bytes for MAC address)
        let (input, mac_bytes) = take(6usize)(input)?;
        let chassis_id = MacAddr::new(
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        );

        Ok((
            input,
            ChassisId {
                chassis_id_type,
                chassis_id,
            },
        ))
    }

    // Serialize function for ChassisId
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the chassis_id_type (1 byte)
        bytes.push(self.chassis_id_type);

        // Serialize the chassis_id (MAC address)
        bytes.extend_from_slice(&[
            self.chassis_id.0,
            self.chassis_id.1,
            self.chassis_id.2,
            self.chassis_id.3,
            self.chassis_id.4,
            self.chassis_id.5,
        ]);

        bytes
    }
}
///////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortId {
    pub port_id_subtype: u8,
    pub port_id: MacAddr,
}

impl PortId {
    // Parse function for PortIdTLV
    pub fn parse(input: &[u8], input_length: u16) -> IResult<&[u8], Self> {
        // Parse the port_id_subtype (1 byte)
        let (input, port_id_subtype) = be_u8(input)?;

        // Ensure that the remaining input length is correct for a MAC address (6 bytes)
        if input.len() < input_length as usize - 1 {
            return Err(NomErr::Failure(nom::error::Error::new(
                input,
                ErrorKind::LengthValue,
            )));
        }

        // Parse the port_id (6 bytes for MAC address)
        let (input, mac_bytes) = take(6usize)(input)?;
        let port_id = MacAddr::new(
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        );

        Ok((
            input,
            PortId {
                port_id_subtype,
                port_id,
            },
        ))
    }

    // Serialize function for PortIdTLV
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the port_id_subtype (1 byte)
        bytes.push(self.port_id_subtype);

        // Serialize the port_id (MAC address)
        bytes.extend_from_slice(&[
            self.port_id.0,
            self.port_id.1,
            self.port_id.2,
            self.port_id.3,
            self.port_id.4,
            self.port_id.5,
        ]);

        bytes
    }
}
///////////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, Eq)]
pub struct TimeToLiveTLV {
    pub ttl: u16, // TTL is 2 bytes in LLDP
}

impl TimeToLiveTLV {
    /// Parse function for `TimeToLiveTLV`
    pub fn parse(input: &[u8], input_length: u16) -> IResult<&[u8], Self> {
        // Ensure the length is correct for TTL (2 bytes)
        if input_length != 2 {
            return Err(NomErr::Failure(nom::error::Error::new(
                input,
                ErrorKind::LengthValue,
            )));
        }

        // Parse the TTL (2 bytes, big-endian)
        let (input, ttl) = be_u16(input)?;

        Ok((input, TimeToLiveTLV { ttl }))
    }

    /// Serialize function for `TimeToLiveTLV`
    pub fn serialize(&self) -> Vec<u8> {
        self.ttl.to_be_bytes().to_vec() // Convert the 2-byte TTL to a vector
    }
}
///////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq)]
pub struct LLDPDU {
    pub payload: Vec<TLV>,
}

impl LLDPDU {
    /// Parse an LLDPDU from a byte slice.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let mut payload = Vec::new();
        let mut remaining_input = input;

        // Parse TLVs until an `EndOfLldpdu` TLV is encountered or input is empty
        while !remaining_input.is_empty() {
            let (next_input, tlv) = TLV::parse(remaining_input)?;
            remaining_input = next_input;

            // Stop parsing if the TLV type is `EndOfLldpdu`
            if matches!(LLDPTLVType::from_u8(tlv.tlv_type), LLDPTLVType::EndOfLldpdu) {
                payload.push(tlv);
                break;
            }

            payload.push(tlv);
        }

        Ok((remaining_input, LLDPDU { payload }))
    }

    /// Serialize an LLDPDU into a vector of bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for tlv in &self.payload {
            bytes.extend_from_slice(&tlv.serialize());
        }

        bytes
    }
}

///////////////////////////////////////////////////////////////////
#[cfg(test)]
mod tests {
    use super::*;
    use crate::lldpdu_codec::LLDPTLVType;
    use crate::tlv_lldpdu_codec::TLV;

    // Verify the correctness of serialization and parsing
    #[test]
    fn test_lldpdu_serialization_and_parsing() {
        let chassis_id = TLV {
            tlv_type: LLDPTLVType::ChassisId.to_u8(),
            tlv_length: 7,
            tlv_value: Some(vec![0x04, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
        };

        let port_id = TLV {
            tlv_type: LLDPTLVType::PortId.to_u8(),
            tlv_length: 7,
            tlv_value: Some(vec![0x03, 0x00, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F]),
        };

        let ttl = TLV {
            tlv_type: LLDPTLVType::TimeToLive.to_u8(),
            tlv_length: 1,
            tlv_value: Some(vec![0x78]),
        };

        let end_of_lldpdu = TLV {
            tlv_type: LLDPTLVType::EndOfLldpdu.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        let unknown_llpdu = TLV {
            tlv_type: LLDPTLVType::Unknown(10).to_u8(),
            tlv_length: 1,
            tlv_value: Some(vec![0xff]),
        };

        let lldpdu = LLDPDU {
            payload: vec![
                chassis_id.clone(),
                port_id.clone(),
                ttl.clone(),
                unknown_llpdu.clone(),
                end_of_lldpdu.clone(),
            ],
        };

        // Serialize the LLDPDU
        let serialized_lldpdu = lldpdu.serialize();
        tracing::info!("Serialized LLDPDU: {:?}", serialized_lldpdu);

        // Parse the serialized LLDPDU
        let parsed_lldpdu = LLDPDU::parse(&serialized_lldpdu).unwrap().1;

        // Ensure the parsed LLDPDU matches the original
        assert_eq!(parsed_lldpdu.payload.len(), 5);
        assert_eq!(parsed_lldpdu.payload[0], chassis_id);
        assert_eq!(parsed_lldpdu.payload[1], port_id);
        assert_eq!(parsed_lldpdu.payload[2], ttl);
        assert_eq!(parsed_lldpdu.payload[3], unknown_llpdu);
        assert_eq!(parsed_lldpdu.payload[4], end_of_lldpdu);
    }

    // Verify serialization and parsing of organizationally specific (unknown) TLV
    #[test]
    fn test_lldpdu_with_unknown_tlv() {
        let unknown_tlv = TLV {
            tlv_type: 0x7F,
            tlv_length: 4,
            tlv_value: Some(vec![0x01, 0x02, 0x03, 0x04]),
        };

        let end_of_lldpdu = TLV {
            tlv_type: LLDPTLVType::EndOfLldpdu.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        };

        let lldpdu = LLDPDU {
            payload: vec![unknown_tlv.clone(), end_of_lldpdu.clone()],
        };

        let serialized = lldpdu.serialize();
        let parsed = LLDPDU::parse(&serialized).unwrap().1;

        assert_eq!(parsed.payload.len(), 2);
        assert_eq!(parsed.payload[0], unknown_tlv);
        assert_eq!(parsed.payload[1], end_of_lldpdu);
    }

    // Verify Chassis ID serialization and parsing
    #[test]
    fn test_chassis_id_serialization_and_parsing() {
        let chassis_id_original = ChassisId {
            chassis_id_type: 10,
            chassis_id: MacAddr::new(0x04, 0x00, 0x1A, 0x2B, 0x3C, 0x4D),
        };
        let chassis_id_bytes: Vec<u8> = vec![0x0a, 0x04, 0x00, 0x1A, 0x2B, 0x3C, 0x4D];
        let chassis_id = ChassisId::parse(&chassis_id_bytes, 7);
        let parsed_chassis_id = chassis_id.unwrap().1;
        assert_eq!(parsed_chassis_id, chassis_id_original);

        let serialized = chassis_id_original.serialize();
        assert_eq!(serialized, chassis_id_bytes);

        let error_parse = ChassisId::parse(&chassis_id_bytes, 9);
        assert!(error_parse.is_err());
    }

    // Verify Port ID serialization and parsing
    #[test]
    fn test_port_id_serialization_and_parsing() {
        let port_id_original = PortId {
            port_id_subtype: 10,
            port_id: MacAddr::new(0x04, 0x00, 0x1A, 0x2B, 0x3C, 0x4D),
        };
        let port_id_bytes: Vec<u8> = vec![0x0a, 0x04, 0x00, 0x1A, 0x2B, 0x3C, 0x4D];
        let port_id = PortId::parse(&port_id_bytes, 7);
        let parsed_port_id = port_id.unwrap().1;
        assert_eq!(parsed_port_id, port_id_original);

        let serialized = port_id_original.serialize();
        assert_eq!(serialized, port_id_bytes);

        let error_parse = PortId::parse(&port_id_bytes, 8);
        assert!(error_parse.is_err());
    }

    // Verify TTL serialization and parsing
    #[test]
    fn test_time_to_live_serialization_and_parsing() {
        let time_to_live_original = TimeToLiveTLV {
            ttl: 10,
        };
        let time_to_live_bytes: Vec<u8> = vec![0x00,0x0a];
        let time_to_live = TimeToLiveTLV::parse(&time_to_live_bytes, 2);
        let parsed_time_to_live = time_to_live.unwrap().1;
        assert_eq!(parsed_time_to_live, time_to_live_original);

        let serialized = time_to_live_original.serialize();
        assert_eq!(serialized, time_to_live_bytes);

        let parse_error = TimeToLiveTLV::parse(&time_to_live_bytes, 3);
        assert!(parse_error.is_err());
    }
}
