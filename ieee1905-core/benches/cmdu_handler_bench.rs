use criterion::{criterion_group, criterion_main, Criterion};
use ieee1905::cmdu::{CMDUType, CMDU};
use ieee1905::cmdu_handler::CMDUHandler;
use ieee1905::cmdu_message_id_generator::get_message_id_generator;
use ieee1905::ethernet_subject_transmission::EthernetSender;
use pnet::datalink::MacAddr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

fn bench_handle_cmdu(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let (handler, cmdu, src, dst, if_mac) = rt.block_on(async {
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

        let src = MacAddr::new(0x10, 0x22, 0x33, 0x44, 0x55, 0x66);
        let dst = MacAddr::new(0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc);
        let if_mac = local_al_mac;

        (handler, cmdu, src, dst, if_mac)
    });

    c.bench_function("cmdu_handler/topology_response", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = handler.handle_cmdu(&cmdu, src, dst, if_mac).await;
        });
    });
}

criterion_group!(benches, bench_handle_cmdu);
criterion_main!(benches);
