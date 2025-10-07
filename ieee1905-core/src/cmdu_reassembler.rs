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

use pnet::datalink::MacAddr;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tokio::task::JoinSet;
use std::collections::{BTreeMap, HashMap};
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Instant;
use crate::cmdu::CMDU;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum CmduReassemblyError {
    EmptyFragments,
    InconsistentMetadata,
    MissingFragments,                   // Missing CMDU fragment in CMDU chain
    MissingLastFragment,                // Missing last CMDU fragment with CMDU.flags == 0x80
    WaitingForMoreFragments,
    MessageComplete,                    // The whole CMDU is completed
    DuplicatedFragment                  // Duplicated value of fragment.fragment noticed
}

#[derive(Debug, Clone)]
struct FragmentBuffer {
    fragments: BTreeMap<u8, CMDU>,
    first_received: Instant,
}

#[derive(Default)]
pub struct CmduReassembler {
    _join_set: JoinSet<()>,
    buffer: Arc<Mutex<HashMap<(MacAddr, u16), FragmentBuffer>>>,
}

impl CmduReassembler {
    pub fn new() -> Self {
        let buffer = Arc::new(Mutex::new(HashMap::<(MacAddr, u16), FragmentBuffer>::new()));
        let buffer_clone = buffer.clone();

        let mut join_set = JoinSet::new();
        join_set.spawn(async move {
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
                            tracing::error!("Reassembly error for {:?}: MissingLastFragment", key);
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
        Self { _join_set: join_set, buffer }
    }

    pub async fn push_fragment(&self, source_mac: MacAddr, fragment: CMDU) -> Option<Result<CMDU, CmduReassemblyError>> {
        tracing::trace!("Pushing fragments {fragment:?}");
        let key = (source_mac, fragment.message_id);
        let mut buffer = self.buffer.lock().await;

        let mut entry = match buffer.entry(key) {
            Entry::Occupied(e) => e,
            Entry::Vacant(e) => e.insert_entry(FragmentBuffer {
                fragments: BTreeMap::new(),
                first_received: Instant::now(),
            }),
        };

        let inserted = entry.get_mut().fragments.insert(fragment.fragment, fragment.clone());
        if inserted.is_some() {
            tracing::trace!("Duplicated fragment: {:?}", fragment.fragment);
            return Some(Err(CmduReassemblyError::DuplicatedFragment));
        }

        if fragment.is_last_fragment() {
            tracing::trace!("All fragments arrived. Generating reassembled CMDU");
            let fragments_map = entry.remove().fragments;
            let fragments: Vec<CMDU> = fragments_map.into_values().collect();
            Some(CMDU::reassemble(fragments))
        } else {
            tracing::trace!("Waiting for more fragments");
            None
        }
    }
}


#[cfg(test)]
pub mod tests {
    use tracing::{error, trace};
    use crate::cmdu::TLV;
    use crate::cmdu_codec::tests::make_dummy_cmdu;
    use tokio::time::sleep;
    use super::*;

    // Create CMDU reassembler instance but don't push any fragments to it
    #[tokio::test]
    async fn test_empty_fragment() {
        let cmdu_reasm = CmduReassembler::new();

        // Wait longer than 3 seconds timeout set in tokio async in new() method
        sleep(Duration::from_secs(4)).await;

        // Check if CMDU reassembler instance still exists after 4 seconds and is empty
        assert!(cmdu_reasm.buffer.lock().await.is_empty());
    }

    // Simulate lost of fragment 2 to verify missing fragment with last flag set.
    #[tokio::test]
    async fn test_simulate_lost_of_fragment_2() {
        // Create simple TLV
        let tlv = TLV {
            tlv_type: 0x01,
            tlv_length: 0,
            tlv_value: None,
        };

        // Create only one CMDU
        let cmdu = CMDU {
            message_version: 0,
            reserved: 0,
            message_type: 0x04,
            message_id: 0x1122,
            fragment: 0,
            flags: 0x00,     // last fragment flag is not set intentionally as this is not last fragment
            payload: tlv.serialize(),
        };

        let cmdu_reasm = CmduReassembler::new();

        // Push the only fragment
        let _ = cmdu_reasm.push_fragment(MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66), cmdu.clone()).await;

        // Expect one fragment in CMDU reassembler buffer before 3 seconds timeout elapsed
        assert!(!cmdu_reasm.buffer.lock().await.is_empty());

        // Wait longer than 3 seconds of timeout in async in new()
        sleep(Duration::from_secs(4)).await;

        // Expect empty CMDU reassembler buffer after 3 seconds timeout elapsed
        // as async function in new() should remove the only existing fragment
        // because of simulating lost of last fragment (should have bit 7 set in CMDU flags)
        assert!(cmdu_reasm.buffer.lock().await.is_empty());
    }

    // Verify removing bad CMDU chain after 3 seconds of timeout
    #[tokio::test]
    async fn test_inserting_two_fragments_without_last_fragment_flag() {
        // Create 2 TLVs
        let tlv1 = TLV {
            tlv_type: 0x01,
            tlv_length: 0,
            tlv_value: None,
        };
        let tlv2 = TLV {
            tlv_type: 0x02,
            tlv_length: 0,
            tlv_value: None,
        };

        // Create chain of 2 CMDUs. Both CMDUs have no last fragment flag set to simulate
        // lost of fragment 3
        let cmdu1 = CMDU {
            message_version: 0,
            reserved: 0,
            message_type: 0x04,
            message_id: 0x1122,
            fragment: 0,
            flags: 0x00,
            payload: tlv1.serialize(),
        };

        let cmdu2 = CMDU {
            message_version: 0,
            reserved: 0,
            message_type: 0x04,
            message_id: 0x1122,
            fragment: 1,
            flags: 0x00,
            payload: tlv2.serialize(),
        };

        let cmdu_reasm = CmduReassembler::new();

        // Add both CMDUs to CMDU reassembler buffer
        let _ = cmdu_reasm.push_fragment(MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66), cmdu1.clone()).await;
        let _ = cmdu_reasm.push_fragment(MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66), cmdu2.clone()).await;

        // Verify that there is one entry in HashMap for MAC: 11:22:33:44:55:66 and message_id 0x1122
        assert_eq!(cmdu_reasm.buffer.lock().await.len(), 1);
        // Verify that there are 2 entries in BTreeMap (2 CMDU fragments)
        assert_eq!(cmdu_reasm.buffer.lock().await.get(&(MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66), 0x1122)).unwrap().fragments.len(), 2);

        // Wait longer that 3 seconds of timeout of async from new()
        sleep(Duration::from_secs(4)).await;

        // After timeout in async from new() there should not be any entry in HashMap
        assert!(cmdu_reasm.buffer.lock().await.is_empty());
    }

    // Check recognition of missed fragment in the middle of CMDU chain
    #[tokio::test]
    async fn test_reassembler_missing_fragment() {
        let mut cmdu0 = make_dummy_cmdu(vec![10, 20]);
        let mut cmdu1 = make_dummy_cmdu(vec![30, 40]);
        let mut cmdu2 = make_dummy_cmdu(vec![50, 60]);

        cmdu0.fragment = 0;
        cmdu1.fragment = 2;         // skip fragment id == 1 to signal missed fragment 1
        cmdu2.fragment = 3;
        cmdu2.flags = 0x80;         // set last fragment flag

        let source_mac = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let fragments = vec![cmdu0, cmdu1, cmdu2];
        let cmdu_reasm = CmduReassembler::new();

        for fragment in fragments.iter() {
            match cmdu_reasm.push_fragment(source_mac, fragment.clone()).await {
                Some(Ok(_)) => {
                    panic!("MissedFragment error expected but CMDU is completely reassembled");
                }
                Some(Err(e)) => {
                    assert_eq!(e, CmduReassemblyError::MissingFragments);
                    error!("Error reassembling CMDU: {:?}", e);
                }
                None => {
                    trace!("Fragment stored. Waiting for more...");
                }
            }
        }
    }
}
//TODO unit test for reassembler and check use cases for out of order fragments, missing fragments, and empty fragments
