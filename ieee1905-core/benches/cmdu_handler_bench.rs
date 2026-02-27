use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ieee1905::cmdu::{CMDUType, CMDU};
use ieee1905::cmdu_handler::CMDUHandler;
use ieee1905::cmdu_message_id_generator::get_message_id_generator;
use ieee1905::ethernet_subject_transmission::EthernetSender;
use ieee1905::topology_manager::{Ieee1905DeviceData, TopologyDatabase, UpdateType};
use pnet::datalink::MacAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

fn bench_handle_cmdu(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let (handler, cmdu, src_missing, src_present, dst, if_mac, local_al_mac) = rt.block_on(async {
        let sender = Arc::new(EthernetSender::new("lo", Arc::new(Mutex::new(()))));
        let msg_ids = get_message_id_generator().await;
        let local_al_mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);

        let handler = CMDUHandler::new(sender, msg_ids, local_al_mac, "lo".to_string()).await;

        let cmdu = CMDU {
            message_version: 0,
            reserved: 0,
            message_type: CMDUType::TopologyResponse.to_u16(),
            message_id: 1,
            fragment: 0,
            flags: 0x80,
            payload: vec![0x00, 0x00, 0x00], // EndOfMessage TLV
        };

        let src_missing = MacAddr::new(0x10, 0x22, 0x33, 0x44, 0x55, 0x66);
        let src_present = MacAddr::new(0x10, 0x22, 0x33, 0x44, 0x55, 0x67);
        let dst = MacAddr::new(0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc);
        let if_mac = local_al_mac;

        (
            handler,
            cmdu,
            src_missing,
            src_present,
            dst,
            if_mac,
            local_al_mac,
        )
    });

    rt.block_on(async {
        let topology_db = TopologyDatabase::get_instance(local_al_mac, "lo".to_string()).await;
        let seeded_device = Ieee1905DeviceData::new(
            src_present,
            src_present,
            None,
            if_mac,
            Some(Vec::new()),
            None,
        );
        let _ = topology_db
            .update_ieee1905_topology(
                seeded_device.clone(),
                UpdateType::DiscoveryReceived,
                None,
                None,
                None,
            )
            .await;
        let _ = topology_db
            .update_ieee1905_topology(
                seeded_device,
                UpdateType::QuerySent,
                Some(cmdu.message_id),
                None,
                None,
            )
            .await;
    });

    c.bench_function("cmdu_handler/topology_response_node_missing", |b| {
        b.to_async(&rt).iter(|| async {
            let result = handler.handle_cmdu(
                black_box(&cmdu),
                black_box(src_missing),
                black_box(dst),
                black_box(if_mac),
            ).await;
            let _ = black_box(result);
        });
    });

    c.bench_function("cmdu_handler/topology_response_node_present", |b| {
        b.to_async(&rt).iter(|| async {
            let result = handler
                .handle_cmdu(
                    black_box(&cmdu),
                    black_box(src_present),
                    black_box(dst),
                    black_box(if_mac),
                )
                .await;
            let _ = black_box(result);
        });
    });
}

criterion_group!(benches, bench_handle_cmdu);
criterion_main!(benches);
