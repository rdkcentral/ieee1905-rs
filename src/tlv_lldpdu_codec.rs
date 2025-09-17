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
    bytes::complete::take,    // Parses a specified number of bytes from the input.
    error::ErrorKind,         // Represents specific parsing error types.
    number::complete::be_u16, // Parses unsigned integers in big-endian format.
    IResult, // Represents the result of a parsing operation, either success or failure.
}; // Alias for errors returned by `nom` parsers.

// Standard library
use std::fmt::Debug; // Allows the `TLV` struct to be formatted for debugging purposes.

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TLV {
    /// The type of the TLV, indicating its semantic meaning (7 bits).
    pub tlv_type: u8,

    /// The length of the TLV value, in bytes (9 bits).
    pub tlv_length: u16,

    /// The payload or value of the TLV.
    pub tlv_value: Option<Vec<u8>>,
}

impl TLV {
    /// Parses a byte slice into a `TLV` instance.
    pub fn parse(input: &[u8]) -> IResult<&[u8], TLV> {
        // Parse the combined Type (7 bits) + Length (9 bits) field (2 bytes).
        let (input, combined) = be_u16(input)?;

        // Extract the Type (7 bits) and Length (9 bits).
        let tlv_type = (combined >> 9) as u8; // Upper 7 bits
        let tlv_length = combined & 0x1FF; // Lower 9 bits

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
            return Err(NomErr::Failure(nom::error::Error::new(
                input,
                ErrorKind::LengthValue,
            )));
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
    /// - 2 bytes for combined `Type` (7 bits) and `Length` (9 bits).
    /// - `tlv_length` bytes for `tlv_value` (if present).
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Pack the `Type` and `Length` into a single 16-bit value.
        let combined = ((self.tlv_type as u16) << 9) | (self.tlv_length & 0x1FF);
        bytes.extend_from_slice(&combined.to_be_bytes());

        // Serialize the `tlv_value` if present.
        if let Some(ref value) = self.tlv_value {
            bytes.extend_from_slice(value);
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::TLV;

    // Verify the correctness of parsing valid data from a slice
    #[test]
    fn test_parse_with_value() {
        let input = &[0x02, 0x07, b'A', b'B', b'C', b'D', b'E', b'F', b'G'];
        let result = TLV::parse(input);

        if let Err(e) = &result {
            println!("Parse error: {:?}", e);
        }

        assert!(result.is_ok());
        let (remaining, tlv) = result.unwrap();
        assert_eq!(remaining.len(), 0);
        assert_eq!(tlv.tlv_type, 1);
        assert_eq!(tlv.tlv_length, 7);
        assert_eq!(
            tlv.tlv_value,
            Some(vec![b'A', b'B', b'C', b'D', b'E', b'F', b'G'])
        );
    }

    // Verify serialization of TLV with valid payload
    #[test]
    fn test_serialize_with_value() {
        let tlv = TLV {
            tlv_type: 1,
            tlv_length: 7,
            tlv_value: Some(vec![0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]),
        };
        let serialized = tlv.serialize();

        // Expect success in serialization process
        assert_eq!(
            serialized,
            vec![0x02, 0x07, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]
        );
    }

    // Verify serialization of TLV without any payload
    #[test]
    fn test_serialize_without_value() {
        let tlv = TLV {
            tlv_type: 1,
            tlv_length: 0,
            tlv_value: None,
        };
        let serialized = tlv.serialize();

        // Expect success in serialization process
        assert_eq!(serialized, vec![0x02, 0x00]);
    }

    // Try to parse TLV with invalid tlv_length value bigger than the real size of provided data
    #[test]
    fn test_parse_invalid_tlv_len_bigger_than_real_one() {
        // tlv_type = 0x01:  tlv_type is made of 7 most significant bits of value from input[0] == 0x02
        // tlv_length = 0x09 while there are only 7 bytes of payload
        let input = &[0x02, 0x09, b'A', b'B', b'C', b'D', b'E', b'F', b'G'];
        let result = TLV::parse(input);

        // Expect error as a result of parsing because not enough data passed in payload
        assert!(result.is_err());
    }

    // Try to parse TLV with invalid tlv_length value smaller than the real size of provided data
    #[test]
    fn test_parse_invalid_tlv_len_smaller_than_real_one() {
        // tlv_type = 0x01:  tlv_type is made of 7 most significant bits of value from input[0] == 0x02
        // tlv_length = 0x06 while there are 8 bytes of payload
        let input = &[0x02, 0x06, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H'];
        let result = TLV::parse(input);
        println!("Parse result: {:?}", result);

        // Expect success as a result of parsing as parser tooks only the number of bytes stored in tlv_length and returns the rest
        assert!(result.is_ok());

        // Expect that parser returns redundant (not needed) data: &['G', 'H']
        assert_eq!(result.unwrap().0, &[b'G', b'H']);
    }
}
