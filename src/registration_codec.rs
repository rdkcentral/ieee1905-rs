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
    number::complete::{be_u8, be_u16},
    error::ErrorKind,
    Err as NomErr,
    IResult,
};
use pnet::datalink::MacAddr;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ServiceOperation {
    Enable = 0x01,
    Disable = 0x02,
}

impl ServiceOperation {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, val) = be_u8(input)?;
        let op = match val {
            0x01 => ServiceOperation::Enable,
            0x02 => ServiceOperation::Disable,
            _ => return Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag))),
        };
        Ok((input, op))
    }

    pub fn serialize(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ServiceType {
    EasyMeshAgent = 0x01,
    EasyMeshController = 0x02
}

impl ServiceType {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, val) = be_u8(input)?;
        let st = match val {
            0x01 => ServiceType::EasyMeshAgent,
            0x02 => ServiceType::EasyMeshController,
             _ => return Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag))),
        };
        Ok((input, st))
    }

    pub fn serialize(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RegistrationResult {
    Unknown = 0x00,
    Success = 0x01,
    NoRangesAvailable = 0x02,
    ServiceNotSupported = 0x03,
    OperationNotSupported = 0x04,
    ControllerAlreadyInNetwork = 0x5,
}

impl RegistrationResult {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, val) = be_u8(input)?;
        let result = match val {
            0x00 => RegistrationResult::Unknown,
            0x01 => RegistrationResult::Success,
            0x02 => RegistrationResult::NoRangesAvailable,
            0x03 => RegistrationResult::ServiceNotSupported,
            0x04 => RegistrationResult::OperationNotSupported,
            0x05 => RegistrationResult::ControllerAlreadyInNetwork,
            _ => return Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag))),
        };
        Ok((input, result))
    }

    pub fn serialize(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AlServiceRegistrationRequest {
    pub service_operation: ServiceOperation,
    pub service_type: ServiceType,
}

impl AlServiceRegistrationRequest {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < 2 {
            return Err(NomErr::Failure(nom::error::Error::new(input, ErrorKind::LengthValue)));
        }

        let (input, service_operation) = ServiceOperation::parse(input)?;
        let (input, service_type) = ServiceType::parse(input)?;
        Ok((input, Self { service_operation, service_type }))
    }

    pub fn serialize(&self) -> Vec<u8> {
        vec![
            self.service_operation.serialize(),
            self.service_type.serialize(),
        ]
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AlServiceRegistrationResponse {
    pub al_mac_address_local: MacAddr,
    pub message_id_range: (u16, u16),
    pub result: RegistrationResult,
}

impl AlServiceRegistrationResponse {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, mac_bytes) = take(6usize)(input)?;
        let mac = MacAddr::new(mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        let (input, start_id) = be_u16(input)?;
        let (input, end_id) = be_u16(input)?;
        let (input, result) = RegistrationResult::parse(input)?;
        Ok((input, Self {
            al_mac_address_local: mac,
            message_id_range: (start_id, end_id),
            result,
        }))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(11);
        buf.extend_from_slice(&self.al_mac_address_local.octets());
        buf.extend_from_slice(&self.message_id_range.0.to_be_bytes());
        buf.extend_from_slice(&self.message_id_range.1.to_be_bytes());
        buf.push(self.result.serialize());
        buf
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TopologyChangeType {
    Add,
    Delete,
}
impl TopologyChangeType {
    pub fn serialize(&self) -> u8 {
        match self {
            TopologyChangeType::Add => 0x01,
            TopologyChangeType::Delete => 0x02,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, value) = be_u8(input)?;
        let change_type = match value {
            0x01 => TopologyChangeType::Add,
            0x02 => TopologyChangeType::Delete,
            _ => return Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Tag))),
        };
        Ok((input, change_type))
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AlTopologyChange {
    pub al_mac_address_remote: MacAddr,
    pub change_type: TopologyChangeType,
}

impl AlTopologyChange {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7);
        buf.extend_from_slice(&self.al_mac_address_remote.octets());
        buf.push(self.change_type.serialize());
        buf
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, mac_bytes) = take(6usize)(input)?;
        let mac = MacAddr::new(mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        let (input, change_type) = TopologyChangeType::parse(input)?;
        Ok((input, Self {
            al_mac_address_remote: mac,
            change_type,
        }))
    }
}


#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    #[should_panic]
    fn test_parse_too_short_registration_request() {
        assert!(AlServiceRegistrationRequest::parse(&[1]).is_ok());
    }

    #[test]
    fn test_parse_proper_registration_request() {
        assert!(AlServiceRegistrationRequest::parse(&[1, 1]).is_ok());
        assert_eq!(AlServiceRegistrationRequest::parse(&[1, 1]).unwrap().1.service_operation, ServiceOperation::Enable);
        assert_eq!(AlServiceRegistrationRequest::parse(&[1, 1]).unwrap().1.service_type, ServiceType::EasyMeshAgent);
    }

    #[test]
    fn test_parse_proper_service_operation() {
        assert!(ServiceOperation::parse(&[2]).is_ok());
    }

    #[test]
    #[should_panic]
    fn test_try_to_parse_inappropriate_service_operation() {
        assert!(ServiceOperation::parse(&[0]).is_ok());
    }

    #[test]
    fn test_parse_proper_service_type() {
        assert!(ServiceType::parse(&[2]).is_ok());
    }

    #[test]
    #[should_panic]
    fn test_try_to_parse_inappropriate_service_type() {
        assert!(ServiceType::parse(&[0]).is_ok());
    }

    #[test]
    fn test_parse_proper_registration_result() {
        assert!(RegistrationResult::parse(&[0]).is_ok());
        assert!(RegistrationResult::parse(&[2]).is_ok());
        assert!(RegistrationResult::parse(&[3]).is_ok());
        assert_eq!(RegistrationResult::parse(&[0]).unwrap().1, RegistrationResult::Unknown);
    }

    #[test]
    #[should_panic]
    fn test_try_to_parse_inappropriate_registration_result() {
        assert!(RegistrationResult::parse(&[6]).is_ok());
    }

    #[test]
    fn test_check_consumption_of_registration_result_parser() {
        // Check if size of returned not used data is correct
        assert_eq!(RegistrationResult::parse(&[4]).unwrap().0.len(), 0);
        assert_eq!(RegistrationResult::parse(&[4, 5]).unwrap().0.len(), 1);
        // Check if not consumed part is properly returned, untouched and unparsed by parser at all
        assert_eq!(RegistrationResult::parse(&[4, 5, 6, 7]).unwrap().0, &[5, 6, 7]);
    }

    #[test]
    fn test_check_consumption_of_registration_request_parser() {
        // Check if size of returned not used data is correct
        assert_eq!(AlServiceRegistrationRequest::parse(&[1, 2]).unwrap().0.len(), 0);
        assert_eq!(AlServiceRegistrationRequest::parse(&[1, 2, 3]).unwrap().0.len(), 1);
        // Check if not consumed part is properly returned, untouched and unparsed by parser at all
        assert_eq!(AlServiceRegistrationRequest::parse(&[1, 2, 3, 4, 5]).unwrap().0, &[3, 4, 5]);
    }

    #[test]
    fn test_registration_response_parse_and_serialize() {
        let mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let mut registration_response_data: Vec<u8> = mac;
        let start: Vec<u8> = vec![0x00, 0x01];
        let end: Vec<u8> = vec![0x00, 0x10];
        let result = RegistrationResult::Success.serialize();

        registration_response_data.append(&mut start.clone());
        registration_response_data.append(&mut end.clone());
        registration_response_data.push(result);

        let parsed = AlServiceRegistrationResponse::parse(&registration_response_data[..]).unwrap().1;

        assert_eq!(parsed.serialize(), registration_response_data);
    }

    #[test]
    fn test_registration_request_parse_and_serialize() {
        let service_operation = ServiceOperation::Enable.serialize();
        let service_type = ServiceType::EasyMeshAgent.serialize();

        let registration_request: Vec<u8> = vec![service_operation, service_type];
        let parsed = AlServiceRegistrationRequest::parse(&registration_request[..]).unwrap().1;

        assert_eq!(parsed.serialize(), registration_request);
    }

    #[test]
    fn test_topology_change_parse_and_serialize_add() {
        let mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let topology_type = TopologyChangeType::Add.serialize();
        let mut topology_change_data: Vec<u8> = mac;

        topology_change_data.push(topology_type);

        let parsed = AlTopologyChange::parse(&topology_change_data).unwrap().1;

        assert_eq!(topology_change_data, parsed.serialize());
    }

    #[test]
    fn test_topology_change_parse_and_serialize_delete() {
        let mac: Vec<u8> = vec![0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02];
        let topology_type = TopologyChangeType::Delete.serialize();
        let mut topology_change_data: Vec<u8> = mac;

        topology_change_data.push(topology_type);

        let parsed = AlTopologyChange::parse(&topology_change_data).unwrap().1;

        assert_eq!(topology_change_data, parsed.serialize());
    }

    #[test]
    fn test_topology_change_type_parse_invalid() {
        let bind: Vec<u8> = vec![5];
        let topology_type = TopologyChangeType::parse(&bind);
        assert!(topology_type.is_err());
    }
}
