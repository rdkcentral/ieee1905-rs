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
    mechanism::{Mechanism, MechanismType, vendor_defined::VendorDefinedMechanism},
    object::{Attribute, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::{AuthPin, Ulong},
};

use crate::cmdu_codec::{EncryptedPayload, MessageIntegrityCode, MicVersion};
use crate::tlv_cmdu_codec::{TLV, TLVTrait};

/// Environment variable holding the PKCS#11 module path.
const MODULE_ENV: &str = "PKCS11_LIB";

/// Environment variable holding the SoftHSM2 user PIN.
const USER_PIN_ENV: &str = "PKCS11_USER_PIN";

// GTK object label and ID
const GTK_LABEL: &str = "1905GTK";
const TK_LABEL: &str = "1905TK";

const GTK_KEY_ID: u8 = 1;
const TK_KEY_ID: u8 = 3;

// HMAC-SHA256 output size
const MIC_SIZE: usize = 32;
const SIV_SIZE: usize = 16;

pub struct CryptoContext {
    session: Arc<Mutex<Session>>,
    gtk_key: ObjectHandle,
    tk_key: ObjectHandle,
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

            let gtk_key = Self::find_key(&session, GTK_LABEL, GTK_KEY_ID, KeyType::GENERIC_SECRET)
                .ok_or_else(|| anyhow!("GTK key not found"))?;
            let tk_key = Self::find_key(&session, TK_LABEL, TK_KEY_ID, KeyType::AES)
                .ok_or_else(|| anyhow!("TK key not found"))?;

            Ok(Self {
                session: Arc::new(Mutex::new(session)),
                gtk_key,
                tk_key,
            })
        })
        .await
    }

    // Encrypt TLVs with AES-SIV
    pub async fn encrypt(
        &self,
        tlvs: &[TLV],
        encryption_transmission_counter: [u8; 6],
    ) -> anyhow::Result<EncryptedPayload> {
        let plaintext = tlvs.iter().flat_map(TLV::serialize).collect::<Vec<_>>();
        let session = self.session.clone().lock_owned().await;
        let tk_key = self.tk_key;

        let mut encrypted = EncryptedPayload {
            encryption_transmission_counter,
            source_1905_al_mac_address: Default::default(),
            destination_1905_al_mac_address: Default::default(),
            payload: Vec::new(),
        };
        let associated_data = encryption_associated_data(&encrypted);

        encrypted.payload = tokio::task::spawn_blocking(move || {
            aes_siv_encrypt(&session, tk_key, &associated_data, &plaintext)
        })
        .await??;

        Ok(encrypted)
    }

    // Decrypt and parse TLVs
    pub async fn decrypt(&self, encrypted: &EncryptedPayload) -> anyhow::Result<Vec<TLV>> {
        let ciphertext = encrypted.payload.clone();
        let associated_data = encryption_associated_data(encrypted);
        let session = self.session.clone().lock_owned().await;
        let tk_key = self.tk_key;

        let plaintext = tokio::task::spawn_blocking(move || {
            aes_siv_decrypt(&session, tk_key, &associated_data, &ciphertext)
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
    pub async fn sign(
        &self,
        tlvs: &[TLV],
        integrity_transmission_counter: [u8; 6],
    ) -> anyhow::Result<MessageIntegrityCode> {
        let mic = MessageIntegrityCode {
            gtk_key_id: GTK_KEY_ID,
            mic_version: MicVersion::Version1,
            integrity_transmission_counter,
            source_1905_al_mac_address: Default::default(),
            code: Vec::new(),
        };
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
    pub async fn verify(&self, tlvs: &[TLV]) -> anyhow::Result<bool> {
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
    fn find_key(session: &Session, label: &str, id: u8, key_type: KeyType) -> Option<ObjectHandle> {
        let attributes = vec![
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(vec![id]),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(key_type),
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

fn encryption_associated_data(encrypted: &EncryptedPayload) -> Vec<Vec<u8>> {
    vec![
        vec![0; 6], // TODO: The first 6 octets of the 1905 CMDU
        encrypted.encryption_transmission_counter.to_vec(),
        encrypted.source_1905_al_mac_address.octets().to_vec(),
        encrypted.destination_1905_al_mac_address.octets().to_vec(),
    ]
}

// AES-SIV implemented with PKCS#11 CKM_AES_CMAC + CKM_AES_CTR
//
// SoftHSM2 does not provide native AES-SIV
// - AES-CMAC: builds and checks the AES-SIV tag
// - AES-CTR: encrypts and decrypts the TLV bytes

// Encrypt bytes with AES-SIV and return SIV || ciphertext
fn aes_siv_encrypt(
    session: &Session,
    key: ObjectHandle,
    associated_data: &[Vec<u8>],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let siv = calculate_siv(session, key, associated_data, plaintext)?;
    let ciphertext = aes_ctr(session, key, &siv, plaintext, true)?;

    Ok([siv.to_vec(), ciphertext].concat())
}

// Decrypt SIV || ciphertext and verify the AES-SIV tag
fn aes_siv_decrypt(
    session: &Session,
    key: ObjectHandle,
    associated_data: &[Vec<u8>],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if ciphertext.len() < SIV_SIZE {
        bail!("AES-SIV payload too short");
    }

    let (siv, ciphertext) = ciphertext.split_at(SIV_SIZE);
    let siv = siv
        .try_into()
        .map_err(|_| anyhow!("invalid AES-SIV tag length"))?;
    let plaintext = aes_ctr(session, key, siv, ciphertext, false)?;
    let expected_siv = calculate_siv(session, key, associated_data, &plaintext)?;

    if *siv != expected_siv {
        bail!("AES-SIV authentication failed");
    }

    Ok(plaintext)
}

// Build the AES-SIV tag from AD and plaintext
// RFC 5297 2.4: "D = dbl(D) xor AES-CMAC(K, Si)"
fn calculate_siv(
    session: &Session,
    key: ObjectHandle,
    associated_data: &[Vec<u8>],
    plaintext: &[u8],
) -> anyhow::Result<[u8; SIV_SIZE]> {
    let mut state = aes_cmac(session, key, &[0; SIV_SIZE])?;

    for data in associated_data {
        state = dbl(state);
        let code = aes_cmac(session, key, data)?;
        xor(&mut state, &code);
    }

    if plaintext.len() >= SIV_SIZE {
        let mut input = plaintext.to_vec();
        let offset = input.len() - SIV_SIZE;
        // RFC 5297 2.4: xor D onto the end of the final input.
        xor(&mut input[offset..], &state);
        aes_cmac(session, key, &input)
    } else {
        state = dbl(state);
        // RFC 5297 2.4: xor dbl(D) with the padded final input.
        xor(&mut state, plaintext);
        state[plaintext.len()] ^= 0x80;
        aes_cmac(session, key, &state)
    }
}

fn aes_cmac(session: &Session, key: ObjectHandle, data: &[u8]) -> anyhow::Result<[u8; SIV_SIZE]> {
    let code = session
        .sign(&Mechanism::AesCMac, key, data)
        .map_err(|e| anyhow!("AES-CMAC failed: {e}"))?;
    code.try_into()
        .map_err(|code: Vec<u8>| anyhow!("AES-CMAC has invalid length: {}", code.len()))
}

fn aes_ctr(
    session: &Session,
    key: ObjectHandle,
    siv: &[u8; SIV_SIZE],
    input: &[u8],
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    #[repr(C)]
    struct AesCtrParams {
        counter_bits: Ulong,
        counter_block: [u8; SIV_SIZE],
    }

    let mut counter_block = *siv;
    counter_block[8] &= 0x7f;
    counter_block[12] &= 0x7f;

    let params = AesCtrParams {
        counter_bits: Ulong::new(128),
        counter_block,
    };

    let mechanism = Mechanism::VendorDefined(VendorDefinedMechanism::new(
        MechanismType::AES_CTR,
        Some(&params),
    ));

    if encrypt {
        session
            .encrypt(&mechanism, key, input)
            .map_err(|e| anyhow!("AES-CTR encryption failed: {e}"))
    } else {
        session
            .decrypt(&mechanism, key, input)
            .map_err(|e| anyhow!("AES-CTR decryption failed: {e}"))
    }
}

// RFC 5297 2.3: double a 128-bit input with left-shift and conditional xor.
fn dbl(block: [u8; SIV_SIZE]) -> [u8; SIV_SIZE] {
    let overflow = block[0] & 0x80 != 0;
    let mut value = u128::from_be_bytes(block) << 1;

    if overflow {
        value ^= 0x87;
    }

    value.to_be_bytes()
}

fn xor(dst: &mut [u8], src: &[u8]) {
    for (dst, src) in dst.iter_mut().zip(src) {
        *dst ^= src;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_siv::{siv::Aes256Siv, KeyInit};

    const TEST_TK_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const TEST_INTEGRITY_COUNTER: [u8; 6] = [0, 0, 0, 0, 0, 1];
    const TEST_ENCRYPTION_COUNTER: [u8; 6] = [0, 0, 0, 0, 0, 1];

    #[tokio::test]
    async fn test_crypto_context_positive() -> anyhow::Result<()> {
        let engine = CryptoContext::get().await?;

        let tlvs = vec![TLV {
            tlv_type: 1,
            tlv_length: 3,
            tlv_value: Some(b"190".to_vec()),
        }];

        let mic = engine.sign(&tlvs, TEST_INTEGRITY_COUNTER).await?;
        let mut signed_tlvs = tlvs.clone();
        signed_tlvs.push(mic.into());
        assert!(engine.verify(&signed_tlvs).await?);

        let encrypted = engine.encrypt(&tlvs, TEST_ENCRYPTION_COUNTER).await?;
        let plaintext = tlvs.iter().flat_map(TLV::serialize).collect::<Vec<_>>();
        assert_eq!(
            encrypted.payload,
            reference_aes_siv_encrypt(&encrypted, &plaintext)?
        );
        assert_eq!(
            reference_aes_siv_decrypt(&encrypted, &encrypted.payload)?,
            plaintext
        );
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

        let mic = engine.sign(&tlvs, TEST_INTEGRITY_COUNTER).await?;
        let mut signed_tlvs = tlvs.clone();
        signed_tlvs.push(mic.into());
        signed_tlvs[0].tlv_value = Some(b"905".to_vec());
        assert!(!engine.verify(&signed_tlvs).await?);

        let encrypted = engine.encrypt(&tlvs, TEST_ENCRYPTION_COUNTER).await?;
        let mut modified = encrypted;
        modified.payload[0] ^= 1;
        assert!(engine.decrypt(&modified).await.is_err());
        Ok(())
    }

    fn reference_aes_siv_encrypt(
        encrypted: &EncryptedPayload,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        reference_aes_siv_cipher()?
            .encrypt(
                encryption_associated_data(encrypted).iter().map(Vec::as_slice),
                plaintext,
            )
            .map_err(|_| anyhow!("AES-SIV reference encryption failed"))
    }

    fn reference_aes_siv_decrypt(
        encrypted: &EncryptedPayload,
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        reference_aes_siv_cipher()?
            .decrypt(
                encryption_associated_data(encrypted).iter().map(Vec::as_slice),
                ciphertext,
            )
            .map_err(|_| anyhow!("AES-SIV reference decryption failed"))
    }

    fn reference_aes_siv_cipher() -> anyhow::Result<Aes256Siv> {
        let mut key = TEST_TK_KEY.to_vec();
        key.extend(TEST_TK_KEY);

        Aes256Siv::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid AES-SIV reference key length"))
    }
}
