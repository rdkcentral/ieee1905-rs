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

use crate::cmdu::{CMDUType, CMDU};
use crate::cmdu_handler::CMDUHandler;
use crate::ethernet_receiver::EthernetReceiverObserver;
use crate::next_task_id;
use pnet::datalink::MacAddr;
use std::sync::Arc;
use tracing::{error, info_span, trace, warn, Instrument};

#[derive(Clone)]
pub struct CMDUObserver {
    handler: Arc<CMDUHandler>,
}

impl CMDUObserver {
    pub fn new(handler: Arc<CMDUHandler>) -> Self {
        Self { handler }
    }
}

impl EthernetReceiverObserver for CMDUObserver {
    fn on_frame(
        &mut self,
        interface_mac: MacAddr,
        frame: &[u8],
        source_mac: MacAddr,
        destination_mac: MacAddr,
    ) {
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
                let handler = Arc::clone(&self.handler); // Explicit type annotation
                                                         //TODO to clean up
                                                         //let interface_name = handler_ref.interface_name.clone(); // --> not needed for now unles we pass the interface to the handler

                tokio::task::spawn(
                    async move {
                        if let Err(e) = handler
                            .handle_cmdu(&cmdu, source_mac, destination_mac, interface_mac)
                            .await
                        {
                            error!("Failed to handle CMDU: {e:?}");
                        }
                    }
                    .instrument(info_span!(parent: None, "handle_cmdu", task = next_task_id())),
                );
            }
            Err(e) => {
                error!("Failed to parse CMDU: {:?}", e);
            }
        }
        tracing::trace!("Processing frame DONE");
    }
}
