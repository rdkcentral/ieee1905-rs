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

use std::sync::Arc;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    object::{Attribute, ObjectClass, KeyType, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};

pub struct CryptoContext {
    pub session: Session,
    pub gtk_key: ObjectHandle,
    pub pmk_key: ObjectHandle,
}

pub static CRYPTO_CONTEXT: Lazy<Arc<Mutex<CryptoContext>>> = Lazy::new(|| {
    let lib_path = "/usr/lib/softhsm/libsofthsm2.so";
    let pin = std::env::var("SOFTHSM_USER_PIN").expect("Missing PIN");

    let pkcs11 = Pkcs11::new(lib_path).expect("Failed to load PKCS#11");
    pkcs11.initialize(CInitializeArgs::OsThreads).expect("Init failed");

    let slot = pkcs11.get_slots_with_token().expect("No slot").remove(0);
    let mut session = pkcs11.open_ro_session(slot).expect("Session failed");

    session
        .login(UserType::User, Some(&AuthPin::new(pin)))
        .expect("Login failed");

    let gtk_key = find_key(&mut session, "1905GTK", 0x01).expect("GTK key not found");
    let pmk_key = find_key(&mut session, "1905PMK", 0x02).expect("PMK key not found");

    Arc::new(Mutex::new(CryptoContext {
        session,
        gtk_key,
        pmk_key,
    }))
});

fn find_key(session: &mut Session, label: &str, id: u8) -> Option<ObjectHandle> {
    let attributes = vec![
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(vec![id]),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
    ];

    let handles = session.find_objects(&attributes).ok()?;
    handles.first().copied()
}
