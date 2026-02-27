use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ieee1905::cmdu::CMDU;
use ieee1905::cmdu_reassembler::CmduReassembler;
use pnet::datalink::MacAddr;
use std::time::Duration;
use tokio::runtime::Runtime;

fn make_fragments(message_id: u16, num_fragments: usize, fragment_payload_size: usize) -> Vec<CMDU> {
    (0..num_fragments)
        .map(|fragment_id| {
            let is_last = fragment_id == num_fragments - 1;
            CMDU {
                message_version: 0,
                reserved: 0,
                message_type: 0x0002,
                message_id,
                fragment: fragment_id as u8,
                flags: if is_last { 0x80 } else { 0x00 },
                payload: vec![fragment_id as u8; fragment_payload_size],
            }
        })
        .collect()
}

fn bench_cmdu_reassembler(c: &mut Criterion) {
    let packets_per_iteration = 64;
    let fragments_per_packet = 16;
    let fragment_payload_size = 512;

    let rt = Runtime::new().expect("failed to create tokio runtime");
    let src = MacAddr::new(0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    let packet_fragments = (0..packets_per_iteration)
        .map(|packet_id| make_fragments(0x2244 + packet_id as u16, fragments_per_packet, fragment_payload_size))
        .collect::<Vec<_>>();

    let reassembler = rt.block_on(async { CmduReassembler::new() });

    let mut group = c.benchmark_group("cmdu_reassembler");
    group.measurement_time(Duration::from_secs(20));
    group.warm_up_time(Duration::from_secs(5));
    group.throughput(Throughput::Bytes(
        (packets_per_iteration * fragments_per_packet * fragment_payload_size) as u64,
    ));

    group.bench_function("reassemble_64_packets_x_16_fragments_x_512B", |b| {
        b.to_async(&rt).iter(|| async {
            let mut total_reassembled_bytes = 0usize;

            for packet in &packet_fragments {
                let mut last_result = None;
                for fragment in packet {
                    last_result = reassembler.push_fragment(src, fragment.clone()).await;
                }

                let assembled = match last_result {
                    Some(Ok(cmdu)) => cmdu,
                    Some(Err(err)) => panic!("unexpected reassembly error: {err:?}"),
                    None => panic!("expected final fragment to trigger reassembly"),
                };
                total_reassembled_bytes += assembled.payload.len();
            }

            black_box(total_reassembled_bytes);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_cmdu_reassembler);
criterion_main!(benches);
