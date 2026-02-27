use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ieee1905::cmdu::{IEEE1905TLVType, TLV as CmduTlv, CMDU};
use ieee1905::cmdu_codec::MessageVersion;
use ieee1905::lldpdu::{LLDPTLVType, TLV as LldpTlv, LLDPDU};

fn build_cmdu_bytes(vendor_tlvs: usize, vendor_data_len: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(
        CmduTlv {
            tlv_type: IEEE1905TLVType::AlMacAddress.to_u8(),
            tlv_length: 6,
            tlv_value: Some(vec![0x10, 0x22, 0x33, 0x44, 0x55, 0x66]),
        }
        .serialize(),
    );

    for i in 0..vendor_tlvs {
        let mut vendor_value = vec![0x00, 0x90, 0x96]; // OUI
        vendor_value.extend(std::iter::repeat_n(i as u8, vendor_data_len));
        payload.extend(
            CmduTlv {
                tlv_type: IEEE1905TLVType::VendorSpecificInfo.to_u8(),
                tlv_length: vendor_value.len() as u16,
                tlv_value: Some(vendor_value),
            }
            .serialize(),
        );
    }

    payload.extend(
        CmduTlv {
            tlv_type: IEEE1905TLVType::EndOfMessage.to_u8(),
            tlv_length: 0,
            tlv_value: None,
        }
        .serialize(),
    );

    CMDU {
        message_version: MessageVersion::Version2013.to_u8(),
        reserved: 0,
        message_type: 0x0002,
        message_id: 0x1234,
        fragment: 0,
        flags: 0x80,
        payload,
    }
    .serialize()
}

fn build_lldpdu_bytes(extra_tlvs: usize, tlv_value_len: usize) -> Vec<u8> {
    let mut payload = vec![
        LldpTlv {
            tlv_type: LLDPTLVType::ChassisId.to_u8(),
            tlv_length: 7,
            tlv_value: Some(vec![0x04, 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]),
        },
        LldpTlv {
            tlv_type: LLDPTLVType::PortId.to_u8(),
            tlv_length: 7,
            tlv_value: Some(vec![0x03, 0x00, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F]),
        },
        LldpTlv {
            tlv_type: LLDPTLVType::TimeToLive.to_u8(),
            tlv_length: 2,
            tlv_value: Some(vec![0x00, 0x78]),
        },
    ];

    for i in 0..extra_tlvs {
        payload.push(LldpTlv {
            tlv_type: LLDPTLVType::Unknown(10 + (i % 20) as u8).to_u8(),
            tlv_length: tlv_value_len as u16,
            tlv_value: Some(vec![i as u8; tlv_value_len]),
        });
    }

    payload.push(LldpTlv {
        tlv_type: LLDPTLVType::EndOfLldpdu.to_u8(),
        tlv_length: 0,
        tlv_value: None,
    });

    LLDPDU { payload }.serialize()
}

fn bench_cmdu_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("codec_parse_cmdu");
    let cases = [("small", 1usize, 16usize), ("medium", 8, 64), ("large", 24, 128)];

    for (name, count, value_len) in cases {
        let bytes = build_cmdu_bytes(count, value_len);
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(name, |b| {
            b.iter(|| {
                let parsed = CMDU::parse(black_box(bytes.as_slice()));
                let _ = black_box(parsed);
            });
        });
    }

    group.finish();
}

fn bench_lldpdu_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("codec_parse_lldpdu");
    let bytes = build_lldpdu_bytes(1, 8);
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function("small", |b| {
        b.iter(|| {
            let parsed = LLDPDU::parse(black_box(bytes.as_slice()));
            let _ = black_box(parsed);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_cmdu_parse, bench_lldpdu_parse);
criterion_main!(benches);
