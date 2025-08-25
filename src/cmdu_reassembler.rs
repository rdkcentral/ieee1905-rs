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
use pnet::datalink::MacAddr;
use tokio::sync::Mutex;
use tokio::time::Duration;

// Standard library
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Instant;

// Internal modules
use crate::cmdu::CMDU;
use crate::task_registry::TASK_REGISTRY;
#[derive(Debug, PartialEq)]
pub enum CmduReassemblyError {
    EmptyFragments,
    InconsistentMetadata,
    MissingFragments,
    MissingEndOfMessage,
}
#[derive(Debug)]
struct FragmentBuffer {
    fragments: BTreeMap<u8, CMDU>,
    first_received: Instant,
}
#[derive(Debug, Default)]
pub struct CmduReassembler {
    buffer: Arc<Mutex<HashMap<(MacAddr, u16), FragmentBuffer>>>,
}

impl CmduReassembler {
    pub async fn new() -> Self {
        let buffer: Arc<Mutex<HashMap<(MacAddr, u16), FragmentBuffer>>> =
        Arc::new(Mutex::new(HashMap::new()));
        let buffer_clone = buffer.clone();

        let task_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(3));

            loop {
                ticker.tick().await;

                let mut buffer = buffer_clone.lock().await;
                let now = Instant::now();

                buffer.retain(|key, entry| {
                    let elapsed = now.duration_since(entry.first_received);

                    if elapsed > Duration::from_secs(3) {
                        if entry.fragments.is_empty() {
                            tracing::error!("Reassembly error for {:?}: EmptyFragments", key);
                        } else if !entry.fragments.values().any(|f| f.is_last_fragment()) {
                            tracing::error!("Reassembly error for {:?}: MissingEndOfMessage", key);
                        } else {
                            let last_id = entry.fragments.keys().max().cloned().unwrap_or(0);
                            if entry.fragments.len() < (last_id + 1) as usize {
                                tracing::error!("Reassembly error for {:?}: MissingFragments", key);
                            }
                        }
                        tracing::trace!("Other CMDU's did not arrive removing the reassembler");
                        false // remove expired entry
                    } else {
                        tracing::trace!("Waiting for rest of the packets!");
                        true // keep
                    }
                });
            }
        });

        TASK_REGISTRY.lock().await.push(task_handle);
        Self { buffer }
    }

    pub async fn push_fragment(&self, source_mac: MacAddr, fragment: CMDU) -> Option<Result<CMDU, CmduReassemblyError>> {
        tracing::trace!("Pushing fragments {fragment:?}");
        let key = (source_mac, fragment.message_id);
        let mut buffer = self.buffer.lock().await;

        let entry = buffer.entry(key).or_insert_with(|| FragmentBuffer {
            fragments: BTreeMap::new(),
            first_received: Instant::now(),
        });

        entry.fragments.insert(fragment.fragment, fragment.clone());

        if fragment.is_last_fragment() {
            tracing::trace!("All fragments arrived. Generating reassembled CMDU");
            let fragments_map = buffer.remove(&key).unwrap().fragments;
            let fragments: Vec<CMDU> = fragments_map.into_values().collect();
            Some(CMDU::reassemble(fragments))
        } else {
            tracing::trace!("Waiting for more fragments");
            None
        }
    }

}
//TODO unit test for reassembler and check use cases for out of order fragments, missing fragments, and empty fragments