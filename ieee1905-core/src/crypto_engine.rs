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
use aes_siv::{siv::Aes128Siv, KeyInit};
use anyhow::{anyhow, bail};
use std::ffi::OsStr;
use std::sync::Arc;
use tokio::sync::{Mutex, OnceCell};

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error as Pkcs11Error, RvError},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};

use crate::cmdu_codec::{EncryptedPayload, MessageIntegrityCode, MicVersion};
use crate::tlv_cmdu_codec::{TLV, TLVTrait};

/// Environment variable holding the PKCS#11 module path.
const MODULE_ENV: &str = "PKCS11_LIB";

/// Environment variable holding the SoftHSM2 user PIN.
const USER_PIN_ENV: &str = "PKCS11_USER_PIN";

// GTK object label and ID
const GTK_LABEL: &str = "1905GTK";

const GTK_KEY_ID: u8 = 1;

// HMAC-SHA256 output size
const MIC_SIZE: usize = 32;

pub struct CryptoContext {
    session: Arc<Mutex<Session>>,
    gtk_key: ObjectHandle,
}

impl CryptoContext {
    // Initialize PKCS#11 and load the active GTK
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

            let gtk_key = Self::find_key(&session, GTK_LABEL, GTK_KEY_ID)
                .ok_or_else(|| anyhow!("GTK key not found"))?;

            Ok(Self {
                session: Arc::new(Mutex::new(session)),
                gtk_key,
            })
        })
        .await
    }

    // Encrypt TLVs with AES-SIV
    pub async fn encrypt(
        &self,
        tlvs: &[TLV],
    ) -> anyhow::Result<EncryptedPayload> {
        let plaintext = tlvs.iter().flat_map(TLV::serialize).collect::<Vec<_>>();
        let session = self.session.clone().lock_owned().await;
        let gtk_key = self.gtk_key;

        let payload = tokio::task::spawn_blocking(move || {
            let key = aes_siv_key(&session, gtk_key)?;
            let mut cipher = Aes128Siv::new_from_slice(&key)
                .map_err(|_| anyhow!("invalid AES-SIV key length"))?;
            cipher
                .encrypt(std::iter::empty::<&[u8]>(), &plaintext)
                .map_err(|_| anyhow!("AES-SIV encryption failed"))
        })
        .await??;

        Ok(EncryptedPayload {
            encryption_transmission_counter: [0; 6],
            source_1905_al_mac_address: Default::default(),
            destination_1905_al_mac_address: Default::default(),
            payload,
        })
    }

    // Decrypt and parse TLVs
    pub async fn decrypt(
        &self,
        encrypted: &EncryptedPayload,
    ) -> anyhow::Result<Vec<TLV>> {
        let ciphertext = encrypted.payload.clone();
        let session = self.session.clone().lock_owned().await;
        let gtk_key = self.gtk_key;

        let plaintext = tokio::task::spawn_blocking(move || {
            let key = aes_siv_key(&session, gtk_key)?;
            let mut cipher = Aes128Siv::new_from_slice(&key)
                .map_err(|_| anyhow!("invalid AES-SIV key length"))?;
            cipher
                .decrypt(std::iter::empty::<&[u8]>(), &ciphertext)
                .map_err(|_| anyhow!("AES-SIV decryption failed"))
        })
        .await??;

        let mut input = plaintext.as_slice();
        let mut tlvs = Vec::new();
        while !input.is_empty() {
            let (remaining, tlv) = TLV::parse(input)
                .map_err(|error| anyhow!("failed to parse decrypted TLV: {error:?}"))?;
            tlvs.push(tlv);
            input = remaining;
        }
        Ok(tlvs)
    }

    // Sign TLVs with HMAC-SHA256 and return a MIC TLV.
    pub async fn sign(&self, tlvs: &[TLV]) -> anyhow::Result<MessageIntegrityCode> {
        let mic = MessageIntegrityCode::find(tlvs).unwrap_or(MessageIntegrityCode {
            gtk_key_id: GTK_KEY_ID,
            mic_version: MicVersion::Version1,
            integrity_transmission_counter: [0; 6],
            source_1905_al_mac_address: Default::default(),
            code: Vec::new(),
        });
        let data = build_mic_input(tlvs, &mic);
        let session = self.session.clone().lock_owned().await;
        let gtk_key = self.gtk_key;

        let code = tokio::task::spawn_blocking(move || {
            // Calculate the HMAC with the active GTK.
            let code = session
                .sign(&Mechanism::Sha256Hmac, gtk_key, &data)
                .map_err(|e| anyhow!("MIC calculation failed: {e}"))?;
            if code.len() != MIC_SIZE {
                bail!("MIC has invalid length: {}", code.len());
            }
            Ok(code)
        })
        .await??;

        Ok(MessageIntegrityCode { code, ..mic })
    }

    ///////////////////////////////////////////////////////////////////////////
    // Verify the MIC TLV in the input TLVs
    pub async fn verify(
        &self,
        tlvs: &[TLV],
    ) -> anyhow::Result<bool> {
        let Some(mic) = MessageIntegrityCode::find(tlvs) else {
            return Ok(false);
        };

        if mic.gtk_key_id != GTK_KEY_ID || mic.mic_version != MicVersion::Version1 {
            return Ok(false);
        }

        if mic.code.len() != MIC_SIZE {
            return Ok(false);
        }

        let data = build_mic_input(tlvs, &mic);
        let session = self.session.clone().lock_owned().await;
        let gtk_key = self.gtk_key;

        tokio::task::spawn_blocking(move || {
            match session.verify(&Mechanism::Sha256Hmac, gtk_key, &data, &mic.code) {
                Ok(()) => Ok(true),
                Err(Pkcs11Error::Pkcs11(RvError::SignatureInvalid, _)) => Ok(false),
                Err(Pkcs11Error::Pkcs11(RvError::SignatureLenRange, _)) => Ok(false),
                Err(e) => Err(anyhow!("MIC verification failed: {e}")),
            }
        })
        .await?
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

fn build_mic_input(tlvs: &[TLV], mic: &MessageIntegrityCode) -> Vec<u8> {
    let cmdu_header = [0; 6]; // TODO: The first 6 octets of the 1905 CMDU
    let mic_tlv_value = mic.serialize();

    let mut mic_input = Vec::new();
    mic_input.extend_from_slice(&cmdu_header);
    mic_input.extend_from_slice(&mic_tlv_value[..13]); // The first 13 octets of the MIC TLV Value
    for tlv in tlvs {
        if tlv.tlv_type != MessageIntegrityCode::TYPE.to_u8() {
            mic_input.extend(tlv.serialize());
        }
    }
    mic_input
}

// Read raw key bytes for the software AES-SIV implementation
fn aes_siv_key(session: &Session, key: ObjectHandle) -> anyhow::Result<Vec<u8>> {
    session
        .get_attributes(key, &[AttributeType::Value])?
        .into_iter()
        .find_map(|attribute| match attribute {
            Attribute::Value(value) => Some(value),
            _ => None,
        })
        .ok_or_else(|| anyhow!("AES-SIV key value is not available"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_crypto_context_positive() -> anyhow::Result<()> {
        let engine = CryptoContext::get().await?;

        let tlvs = vec![TLV {
            tlv_type: 1,
            tlv_length: 3,
            tlv_value: Some(b"190".to_vec()),
        }];

        let mic = engine.sign(&tlvs).await?;
        let mut signed_tlvs = tlvs.clone();
        signed_tlvs.push(mic.into());
        assert!(engine.verify(&signed_tlvs).await?);

        let encrypted = engine.encrypt(&tlvs).await?;
        assert_eq!(engine.decrypt(&encrypted).await?, tlvs);
        Ok(())
    }

    #[tokio::test]
    async fn test_crypto_context_negative() -> anyhow::Result<()> {
        let engine = CryptoContext::get().await?;

        let tlvs = vec![TLV {
            tlv_type: 1,
            tlv_length: 3,
            tlv_value: Some(b"190".to_vec()),
        }];

        let mic = engine.sign(&tlvs).await?;
        let mut signed_tlvs = tlvs.clone();
        signed_tlvs.push(mic.into());
        signed_tlvs[0].tlv_value = Some(b"905".to_vec());
        assert!(!engine.verify(&signed_tlvs).await?);

        let encrypted = engine.encrypt(&tlvs).await?;
        let mut modified = encrypted;
        modified.payload[0] ^= 1;
        assert!(engine.decrypt(&modified).await.is_err());
        Ok(())
    }
}
