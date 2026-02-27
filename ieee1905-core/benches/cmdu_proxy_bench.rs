use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ieee1905::cmdu::{IEEE1905TLVType, TLV, CMDU};
use ieee1905::cmdu_codec::{CMDUFragmentation, MessageVersion};

fn build_payload(num_tlvs: usize, tlv_value_len: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    for i in 0..num_tlvs {
        let tlv = TLV {
            tlv_type: (0x10 + (i % 32) as u8),
            tlv_length: tlv_value_len as u16,
            tlv_value: Some(vec![i as u8; tlv_value_len]),
        };
        payload.extend(tlv.serialize());
    }

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

fn build_cmdu() -> CMDU {
    CMDU {
        message_version: MessageVersion::Version2013.to_u8(),
        reserved: 0,
        message_type: 0x0002,
        message_id: 0x1234,
        fragment: 0,
        flags: 0x80,
        payload: build_payload(24, 80),
    }
}

fn bench_cmdu_proxy_fragment_serialize(c: &mut Criterion) {
    let cmdu = build_cmdu();
    let input_bytes = cmdu.serialize().len() as u64;

    let mut group = c.benchmark_group("cmdu_proxy_fragment");
    group.throughput(Throughput::Bytes(input_bytes));
    group.bench_function("byte_boundary_serialize", |b| {
        b.iter(|| {
            let fragments = cmdu
                .clone()
                .fragment(CMDUFragmentation::ByteBoundary, 1500)
                .expect("fragmentation should succeed");

            let total_bytes = fragments
                .into_iter()
                .map(|f| f.serialize().len())
                .sum::<usize>();
            black_box(total_bytes);
        });
    });
    group.finish();
}

fn bench_cmdu_proxy_parse_fragment_serialize(c: &mut Criterion) {
    let serialized = build_cmdu().serialize();
    let input_bytes = serialized.len() as u64;

    let mut group = c.benchmark_group("cmdu_proxy_parse_fragment");
    group.throughput(Throughput::Bytes(input_bytes));
    group.bench_function("tlv_boundary_serialize", |b| {
        b.iter(|| {
            let (_, parsed) = CMDU::parse(&serialized).expect("parse should succeed");
            let fragments = parsed
                .fragment(CMDUFragmentation::TLVBoundary, 1500)
                .expect("fragmentation should succeed");

            let total_bytes = fragments
                .into_iter()
                .map(|f| f.serialize().len())
                .sum::<usize>();
            black_box(total_bytes);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_cmdu_proxy_fragment_serialize,
    bench_cmdu_proxy_parse_fragment_serialize
);
criterion_main!(benches);
