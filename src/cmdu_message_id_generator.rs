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
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;
use tracing::{debug, info}; // Import tracing

/// A global Message ID generator.
pub struct MessageIdGenerator {
    counter: Mutex<u16>,
}

impl MessageIdGenerator {
    /// Initialize the generator with the starting value.
    pub fn new() -> Self {
        info!("Initializing MessageIdGenerator with starting value 0x0001");
        Self {
            counter: Mutex::new(0x0001),
        }
    }

    /// Get the next message ID, cycling back to 0x0001 after 0xFFFF.
    pub fn next_id(&self) -> u16 {
        let mut counter = self.counter.lock().unwrap();
        let current_id = *counter;

        // Log the generated ID
        debug!("Generated Message ID: {:#06X}", current_id);

        // Update the counter using modulo 2^16
        *counter = counter.wrapping_add(1);

        current_id
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
//TODO creation of unittests check it doesnt get overloaded and works as ring when the last message is reached
//TODO add a test to check that the ID is reset to 0x0001 after