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
use anyhow::{anyhow, bail};
use std::ffi::OsStr;
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error as Pkcs11Error, RvError},
    mechanism::{Mechanism, aead::GcmParams},
    object::{Attribute, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::{AuthPin, Ulong},
};

/// Environment variable holding the PKCS#11 module path.
const MODULE_ENV: &str = "PKCS11_LIB";

/// Environment variable holding the SoftHSM2 user PIN.
const USER_PIN_ENV: &str = "PKCS11_USER_PIN";

/// Length in bytes of the AES-GCM IV that is prepended to every ciphertext.
const AES_GCM_IV_LEN: usize = 12;

/// Length in bits of the AES-GCM authentication tag.
const AES_GCM_TAG_BITS: u64 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// Group Temporal Key — multicast traffic.
    Gtk,
    /// Pairwise Master Key.
    Pmk,
    /// Pairwise Transient Key — unicast traffic.
    Ptk,
}

pub struct CryptoContext {
    session: Arc<Mutex<Session>>,
    gtk_key: ObjectHandle,
    pmk_key: ObjectHandle,
    ptk_key: ObjectHandle,
}

impl CryptoContext {
    ///////////////////////////////////////////////////////////////////////////
    pub async fn get() -> anyhow::Result<&'static Self> {
        static CELL: OnceCell<CryptoContext> = OnceCell::const_new();

        CELL.get_or_try_init(|| async {
            let pkcs11_module = std::env::var_os(MODULE_ENV);
            let pkcs11_module = pkcs11_module
                .as_deref()
                .unwrap_or(OsStr::new("/usr/lib/softhsm/libsofthsm2.so"));

            let pkcs11_pin = std::env::var(USER_PIN_ENV)
                .map_err(|e| anyhow!("missing `{USER_PIN_ENV}` environment variable: {e}"))?;

            let pkcs11 = Pkcs11::new(pkcs11_module)
                .map_err(|e| anyhow!("failed to load PKCS#11 module: {e}"))?;

            pkcs11
                .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                .map_err(|e| anyhow!("failed to initialize PKCS#11: {e}"))?;

            let slot = pkcs11
                .get_slots_with_token()
                .map_err(|e| anyhow!("failed to enumerate PKCS#11 slots: {e}"))?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("no PKCS#11 token present"))?;

            let session = pkcs11
                .open_ro_session(slot)
                .map_err(|e| anyhow!("failed to open PKCS#11 session: {e}"))?;

            session
                .login(UserType::User, Some(&AuthPin::new(pkcs11_pin.into())))
                .map_err(|e| anyhow!("failed to log in to token: {e}"))?;

            let gtk_key = Self::find_key(&session, "1905GTK", 0x01)
                .ok_or_else(|| anyhow!("GTK key not found"))?;
            let pmk_key = Self::find_key(&session, "1905PMK", 0x02)
                .ok_or_else(|| anyhow!("PMK key not found"))?;
            let ptk_key = Self::find_key(&session, "1905PTK", 0x03)
                .ok_or_else(|| anyhow!("PTK key not found"))?;

            Ok(Self {
                session: Arc::new(Mutex::new(session)),
                gtk_key,
                pmk_key,
                ptk_key,
            })
        })
        .await
    }

    ///////////////////////////////////////////////////////////////////////////
    pub async fn encrypt(
        &self,
        key: KeyKind,
        plaintext: impl Into<Vec<u8>>,
        aad: impl Into<Vec<u8>>,
    ) -> anyhow::Result<Vec<u8>> {
        let plaintext = plaintext.into();
        let aad = aad.into();
        let handle = self.key_handle(key);
        let session = self.session.clone().lock_owned().await;

        let task = tokio::task::spawn_blocking(move || {
            let mut iv = session
                .generate_random_vec(AES_GCM_IV_LEN as u32)
                .map_err(|e| anyhow!("failed to generate IV: {e}"))?;

            let params = GcmParams::new(&mut iv, &aad, Ulong::new(AES_GCM_TAG_BITS as _))
                .map_err(|e| anyhow!("failed to generate GCM parameters: {e}"))?;

            let ciphertext = session
                .encrypt(&Mechanism::AesGcm(params), handle, &plaintext)
                .map_err(|e| anyhow!("encrypt operation failed: {e}"))?;

            Ok([iv, ciphertext].concat())
        });
        task.await?
    }

    ///////////////////////////////////////////////////////////////////////////
    pub async fn decrypt(
        &self,
        key: KeyKind,
        data: impl Into<Vec<u8>>,
        aad: impl Into<Vec<u8>>,
    ) -> anyhow::Result<Vec<u8>> {
        let data = data.into();
        let aad = aad.into();
        let handle = self.key_handle(key);
        let session = self.session.clone().lock_owned().await;

        let task = tokio::task::spawn_blocking(move || {
            let Some((iv, body)) = data.split_first_chunk::<AES_GCM_IV_LEN>() else {
                bail!("ciphertext too short");
            };

            let mut iv = *iv;
            let params = GcmParams::new(&mut iv, &aad, Ulong::new(AES_GCM_TAG_BITS as _))
                .map_err(|e| anyhow!("failed to generate GCM parameters: {e}"))?;

            session
                .decrypt(&Mechanism::AesGcm(params), handle, body)
                .map_err(|e| anyhow!("decrypt operation failed: {e}"))
        });
        task.await?
    }

    ///////////////////////////////////////////////////////////////////////////
    pub async fn sign(&self, key: KeyKind, data: impl Into<Vec<u8>>) -> anyhow::Result<Vec<u8>> {
        let data = data.into();
        let handle = self.key_handle(key);
        let session = self.session.clone().lock_owned().await;

        let task = tokio::task::spawn_blocking(move || {
            session
                .sign(&Mechanism::AesCMac, handle, &data)
                .map_err(|e| anyhow!("sign operation failed: {e}"))
        });
        task.await?
    }

    ///////////////////////////////////////////////////////////////////////////
    pub async fn verify(
        &self,
        key: KeyKind,
        data: impl Into<Vec<u8>>,
        tag: impl Into<Vec<u8>>,
    ) -> anyhow::Result<bool> {
        let data = data.into();
        let tag = tag.into();
        let handle = self.key_handle(key);
        let session = self.session.clone().lock_owned().await;

        let task = tokio::task::spawn_blocking(move || {
            match session.verify(&Mechanism::AesCMac, handle, &data, &tag) {
                Ok(()) => Ok(true),
                Err(Pkcs11Error::Pkcs11(RvError::SignatureInvalid, _)) => Ok(false),
                Err(Pkcs11Error::Pkcs11(RvError::SignatureLenRange, _)) => Ok(false),
                Err(e) => Err(anyhow!("verify operation failed: {e}")),
            }
        });
        task.await?
    }

    ///////////////////////////////////////////////////////////////////////////
    fn key_handle(&self, kind: KeyKind) -> ObjectHandle {
        match kind {
            KeyKind::Gtk => self.gtk_key,
            KeyKind::Pmk => self.pmk_key,
            KeyKind::Ptk => self.ptk_key,
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    fn find_key(session: &Session, label: &str, id: u8) -> Option<ObjectHandle> {
        let attributes = vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(vec![id]),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
        ];

        let handles = session.find_objects(&attributes).ok()?;
        handles.first().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_crypto_context_positive() -> anyhow::Result<()> {
        let engine = CryptoContext::get().await?;

        let msg: &[u8] = b"IEEE 1905.1 CryptoContext test";
        let aad: &[u8] = b"1905-header";

        for key in [KeyKind::Gtk, KeyKind::Pmk, KeyKind::Ptk] {
            let sealed = engine.encrypt(key, msg, aad).await?;
            let opened = engine.decrypt(key, sealed.as_slice(), aad).await?;
            assert_eq!(opened, msg, "{key:?}: decrypt did not match plaintext");

            let tag = engine.sign(key, msg).await?;
            let verified = engine.verify(key, msg, tag.as_slice()).await?;
            assert!(verified, "{key:?}: valid MAC was rejected");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_crypto_context_negative() -> anyhow::Result<()> {
        let engine = CryptoContext::get().await?;

        let msg_good: &[u8] = b"IEEE 1905.1 CryptoContext test [good]";
        let msg_bad: &[u8] = b"IEEE 1905.1 CryptoContext test [bad]";
        let aad_good: &[u8] = b"1905-header-good";
        let aad_bad: &[u8] = b"1905-header-bad";

        for key in [KeyKind::Gtk, KeyKind::Pmk, KeyKind::Ptk] {
            let sealed = engine.encrypt(key, msg_good, aad_good).await?;
            let opened = engine.decrypt(key, sealed.as_slice(), aad_bad).await;
            assert!(opened.is_err(), "{key:?}: decrypted with wrong aad");

            let tag = engine.sign(key, msg_good).await?;
            let verified = engine.verify(key, msg_bad, tag.as_slice()).await?;
            assert!(!verified, "{key:?}: verified wrong message");
        }
        Ok(())
    }
}
