use ieee1905::cmdu::{IEEE1905TLVType, TLV, CMDU};
use ieee1905::cmdu_codec::MessageVersion;
use ieee1905::sdu_codec::SDU;
use pnet::datalink::MacAddr;

fn build_cmd_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(
        TLV {
            tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
            tlv_length: 6,
            tlv_value: Some(vec![0x10, 0x22, 0x33, 0x44, 0x55, 0x66]),
        }
        .serialize(),
    );
    payload.extend(
        TLV {
            tlv_type: IEEE1905TLVType::VendorSpecificInfo.to_u8(),
            tlv_length: 8,
            tlv_value: Some(vec![0x00, 0x90, 0x96, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        }
        .serialize(),
    );
    payload.extend(
        TLV {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        }
        .serialize(),
    );
    payload
}

fn make_sdu_from_cmdu(cmdu: CMDU) -> SDU {
    SDU {
        source_al_mac_address: MacAddr::new(0x02, 0x42, 0xc0, 0xa8, 0x64, 0x01),
        destination_al_mac_address: MacAddr::new(0x02, 0x42, 0xc0, 0xa8, 0x64, 0x02),
        is_fragment: 0,
        is_last_fragment: 1,
        fragment_id: 0,
        payload: cmdu.serialize(),
    }
}

#[test]
fn echoed_sdu_keeps_cmdu_payload_equivalent() {
    let original_cmdu = CMDU {
        message_version: MessageVersion::Version2020.to_u8(),
        reserved: 0,
        message_type: 0x0004,
        message_id: 0x1234,
        fragment: 0,
        flags: 0x80,
        payload: build_cmd_payload(),
    };
    let original_sdu = make_sdu_from_cmdu(original_cmdu.clone());

    // Mirror receiver behavior: parse SDU -> parse CMDU -> force Version2013 -> serialize back.
    let (_, parsed_sdu) = SDU::parse(&original_sdu.serialize()).expect("SDU parse should succeed");
    let (_, mut parsed_cmdu) = CMDU::parse(&parsed_sdu.payload).expect("CMDU parse should succeed");
    parsed_cmdu.message_version = MessageVersion::Version2013.to_u8();
    let echoed_sdu = make_sdu_from_cmdu(parsed_cmdu);

    // Mirror transmitter comparison semantics: compare CMDU payload bytes only.
    let (_, sent_sdu) = SDU::parse(&original_sdu.serialize()).expect("sent SDU parse should succeed");
    let (_, echoed_sdu_parsed) =
        SDU::parse(&echoed_sdu.serialize()).expect("echoed SDU parse should succeed");
    let (_, sent_cmdu) = CMDU::parse(&sent_sdu.payload).expect("sent CMDU parse should succeed");
    let (_, echoed_cmdu) =
        CMDU::parse(&echoed_sdu_parsed.payload).expect("echoed CMDU parse should succeed");

    assert_eq!(sent_cmdu.payload, echoed_cmdu.payload);
}
