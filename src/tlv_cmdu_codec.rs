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
    bytes::complete::take,      // Parses a specified number of bytes from the input.
    error::ErrorKind,            // Represents specific parsing error types.
    number::complete::{be_u8, be_u16}, // Parses unsigned integers in big-endian format.
    IResult,                     // Represents the result of a parsing operation, either success or failure.
};
use nom::Err as NomErr;           // Alias for errors returned by `nom` parsers.

// Standard library
use std::fmt::Debug;              // Allows the `TLV` struct to be formatted for debugging purposes.



///////////////////////////////////////////////////////////////////////////
/// A `TLV` represents a single Type-Length-Value structure commonly used
/// in networking protocols. It consists of:
/// - `tlv_type`: The type of the TLV (1 byte).
/// - `tlv_length`: The length of the `tlv_value` in bytes (2 bytes).
/// - `tlv_value`: The actual value or payload of the TLV (variable length).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TLV {
    /// The type of the TLV, indicating its semantic meaning.
    pub tlv_type: u8,

    /// The length of the TLV value, in bytes.
    pub tlv_length: u16,

    /// The payload or value of the TLV.
    pub tlv_value: Option<Vec<u8>>,
}

impl TLV {
    /// Parses a byte slice into a `TLV` instance.
    pub fn parse(input: &[u8]) -> IResult<&[u8], TLV> {
        // Parse the TLV type (1 byte).
        let (input, tlv_type) = be_u8(input)?;

        // Parse the TLV length (2 bytes, big-endian).
        let (input, tlv_length) = be_u16(input)?;

        // Handle the case where `tlv_length` is 0 (no value).
        if tlv_length == 0 {
            return Ok((
                input,
                TLV {
                    tlv_type,
                    tlv_length,
                    tlv_value: None,
                },
            ));
        }

        // Ensure the remaining input is sufficient for the specified value length.
        if input.len() < tlv_length as usize {
            tracing::error!("Expected {tlv_length} but got only {}",input.len());
            return Err(NomErr::Failure(nom::error::Error::new(input, ErrorKind::LengthValue)));
        }

        // Extract the TLV value based on the parsed length.
        let (input, tlv_value) = take(tlv_length as usize)(input)?;

        Ok((
            input,
            TLV {
                tlv_type,
                tlv_length,
                tlv_value: Some(tlv_value.to_vec()),
            },
        ))
    }

    /// Serializes the `TLV` instance into a vector of bytes.
    ///
    /// The serialized format is:
    /// - 1 byte for `tlv_type`.
    /// - 2 bytes for `tlv_length` (big-endian).
    /// - `tlv_length` bytes for `tlv_value` (if present).
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the `tlv_type` field.
        bytes.push(self.tlv_type);

        // Serialize the `tlv_length` field (big-endian).
        bytes.extend_from_slice(&self.tlv_length.to_be_bytes());

        // Serialize the `tlv_value` if present.
        if let Some(ref value) = self.tlv_value {
            bytes.extend_from_slice(value);
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use nom::error::ErrorKind;
    use super::TLV;

    #[test]
    fn test_parse_with_value() {
        let input = &[0x01, 0x00, 0x03, 0x41, 0x42, 0x43]; // TLV: type=1, length=3, value="ABC"
        let result = TLV::parse(input);
        assert!(result.is_ok());
        let (remaining, tlv) = result.unwrap();
        assert_eq!(remaining.len(), 0);
        assert_eq!(tlv.tlv_type, 1);
        assert_eq!(tlv.tlv_length, 3);
        assert_eq!(tlv.tlv_value, Some(vec![0x41, 0x42, 0x43]));
    }

    #[test]
    fn test_parse_without_value() {
        let input = &[0x01, 0x00, 0x00]; // TLV: type=1, length=0, no value
        let result = TLV::parse(input);
        assert!(result.is_ok());
        let (remaining, tlv) = result.unwrap();
        assert_eq!(remaining.len(),0);
        assert_eq!(tlv.tlv_type, 1);
        assert_eq!(tlv.tlv_length, 0);
        assert_eq!(tlv.tlv_value, None);
    }

    #[test]
    fn test_serialize_with_value() {
        let tlv = TLV {
            tlv_type: 1,
            tlv_length: 3,
            tlv_value: Some(vec![0x41, 0x42, 0x43]),
        };
        let serialized = tlv.serialize();
        assert_eq!(serialized, vec![0x01, 0x00, 0x03, 0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_serialize_without_value() {
        let tlv = TLV {
            tlv_type: 1,
            tlv_length: 0,
            tlv_value: None,
        };
        let serialized = tlv.serialize();
        assert_eq!(serialized, vec![0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_try_to_parse_not_enough_data() {
        let tlv = TLV {
            tlv_type: 1,
            tlv_length: 4,
            tlv_value: Some(vec![0x41, 0x42, 0x43]),
        };
        let serialized = tlv.serialize();
        let parsed = TLV::parse(&serialized);

        match parsed {
            Ok(_) => {
               panic!("Expected parsing to fail due to insufficient data, but it succeeded.")
            }
            Err(nom::Err::Failure(e)) => {
                assert_eq!(e.code, ErrorKind::LengthValue);
            },
            Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => {
                panic!("Expected parsing to fail with LengthValue error, but it failed with a different error.");
            }
        }
    }
}
//TODO create unit test when the data is more than the length specified in TLV