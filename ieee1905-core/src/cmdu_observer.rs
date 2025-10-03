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

use tracing::{error, trace, warn};
use async_trait::async_trait;
use pnet::datalink::MacAddr;
use std::sync::Arc;
use tokio::task::JoinSet;
use crate::cmdu::{CMDU, CMDUType};
use crate::cmdu_handler::CMDUHandler;
use crate::ethernet_subject_reception::EthernetFrameObserver;

pub struct CMDUObserver {
    handler: Arc<CMDUHandler>,
    join_set: JoinSet<()>,
}

impl CMDUObserver {
    pub fn new(handler: Arc<CMDUHandler>) -> Self {
        Self { handler, join_set: JoinSet::new() }
    }

    fn release_finished_tasks(&mut self) {
        while self.join_set.try_join_next().is_some() {}
    }
}

#[async_trait]
impl EthernetFrameObserver for CMDUObserver {
    async fn on_frame(&mut self, interface_mac: MacAddr, frame: &[u8], source_mac: MacAddr, destination_mac: MacAddr) {
        let frame_owned = frame.to_vec();
        tracing::trace!("Parsing CMDU on_frame <{frame_owned:?}>");
        match CMDU::parse(&frame_owned) {
            Ok((_, cmdu)) => {
                let cmdu_type = CMDUType::from_u16(cmdu.message_type);

                // **Prevent loops by ignoring frames originating from the same interface, this replace all loop prevention that we can remove from the rest of the code**
                if source_mac == interface_mac {
                    warn!(
                        "Loop detected: Discarding frame from source_mac={} (same as interface_mac={}), CMDU type: {:?}",
                        source_mac, interface_mac, cmdu_type
                    );
                    return;
                }

                trace!("Processing CMDU type: {cmdu_type:?}");
                let handler_ref: Arc<CMDUHandler> = Arc::clone(&self.handler); // Explicit type annotation
                //TODO to clean up
                //let interface_name = handler_ref.interface_name.clone(); // --> not needed for now unles we pass the interface to the handler

                self.release_finished_tasks();
                self.join_set.spawn(async move {
                    if let Err(e) = handler_ref.handle_cmdu(&cmdu, source_mac, destination_mac).await {
                        error!("Failed to handle CMDU: {e:?}");
                    }
                });
            }
            Err(e) => {
                error!("Failed to parse CMDU: {:?}", e);
            }
        }
        tracing::trace!("Processing frame DONE");
    }

    fn get_ethertype(&self) -> u16 {
        0x893A // IEEE 1905 CMDU EtherType
    }
}
