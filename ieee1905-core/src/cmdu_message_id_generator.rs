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
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::sync::OnceCell;
use tracing::{debug, info}; // Import tracing

/// A global Message ID generator.
pub struct MessageIdGenerator {
    counter: AtomicU16,
}

impl MessageIdGenerator {
    /// Initialize the generator with the starting value.
    pub fn new() -> Self {
        info!("Initializing MessageIdGenerator with starting value 0x0001");
        Self {
            counter: AtomicU16::new(0),
        }
    }

    /// Get the next message ID, cycling back to 0x0001 after 0xFFFF.
    pub fn next_id(&self) -> u16 {
        // Update the counter using modulo 2^16 but not 0 (atomics always wrap)
        let mut id = self.counter.fetch_add(1, Ordering::Relaxed);
        while id == 0 {
            id = self.counter.fetch_add(1, Ordering::Relaxed);
        }

        // Log the generated ID
        debug!("Generated Message ID: {id:#06X}");
        id
    }
}

impl Default for MessageIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// A global instance of the `MessageIdGenerator`.
pub static MESSAGE_ID_GENERATOR: OnceCell<Arc<MessageIdGenerator>> = OnceCell::const_new();

/// Global `MessageIdGenerator` instance (async version).
pub async fn get_message_id_generator() -> Arc<MessageIdGenerator> {
    let instance = MESSAGE_ID_GENERATOR
        .get_or_init(|| async {
            info!("Creating global MessageIdGenerator instance");
            Arc::new(MessageIdGenerator::new())
        })
        .await
        .clone();

    info!("Global MessageIdGenerator instance accessed");
    instance
}

#[cfg(test)]
pub mod tests {
    use super::*;

    // Check correctness of generating consecutive message id values
    // and u16 type overflow handling
    #[tokio::test]
    async fn test_check_message_id_value_overflow() {
        let gen = get_message_id_generator().await;

        assert_eq!(gen.next_id(), 1);
        assert_eq!(gen.next_id(), 2);

        // Rewind u16 type values to the value of 0xFFFE (near the last value of u16)
        for _i in 0u32..(u16::MAX as u32 - 4) {
            let _ = gen.next_id();
        }

        assert_eq!(gen.next_id(), 0xFFFE);
        assert_eq!(gen.next_id(), 0xFFFF);  // last value of u16 type

        // Expect counter overflow and correcting action of the value after overflow
        // The next value after 0xFFFF should be 1 (the value of message id == 0 should be skipped)
        assert_eq!(gen.next_id(), 1);
        assert_eq!(gen.next_id(), 2);
    }
}
