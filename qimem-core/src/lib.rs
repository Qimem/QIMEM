use base64::Engine as _;
use qimem_crypto::{hkdf_sha256_contextual, kyber_encapsulate, Aes256GcmEncryptor, Ciphertext, Encryptor, KeyExchange, SharedSecret, X25519Exchange};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("crypto: {0}")]
    Crypto(#[from] qimem_crypto::CryptoError),
    #[error("infra request failed")]
    Infra,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub wrapped_dek_b64: Option<String>,
    pub key_version: Option<i32>,
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HybridSession {
    pub session_key_b64: String,
    pub encapsulated_key_b64: String,
    pub metadata: SessionMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub algorithms: &'static str,
}

pub fn encrypt_local(plaintext: &[u8], dek: &[u8]) -> Result<Envelope, CoreError> {
    let cipher = Aes256GcmEncryptor::encrypt(dek, plaintext)?;
    Ok(Envelope {
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(cipher.body),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(cipher.nonce),
        wrapped_dek_b64: None,
        key_version: None,
        algorithm: "aes-256-gcm".to_string(),
    })
}

pub fn decrypt_local(envelope: &Envelope, dek: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let body = base64::engine::general_purpose::STANDARD
        .decode(&envelope.ciphertext_b64)
        .map_err(|_| CoreError::Infra)?;
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(&envelope.nonce_b64)
        .map_err(|_| CoreError::Infra)?;
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| CoreError::Infra)?;
    let plaintext = Aes256GcmEncryptor::decrypt(dek, &Ciphertext { nonce, body })?;
    Ok(plaintext)
}

pub fn hybrid_pq_session(peer_x25519_public_key: &[u8], infra_kyber_public_key: &[u8]) -> Result<HybridSession, CoreError> {
    let local = X25519Exchange::generate();
    let x_shared = X25519Exchange::derive_shared(&local.private_key, peer_x25519_public_key)?;
    let (encapsulated, kyber_shared) = kyber_encapsulate(infra_kyber_public_key)?;
    let mut context = Vec::new();
    context.extend_from_slice(b"qimem-core-hybrid-context-v1");
    context.extend_from_slice(&local.public_key);
    context.extend_from_slice(peer_x25519_public_key);
    context.extend_from_slice(infra_kyber_public_key);
    let session_key = hkdf_sha256_contextual(&x_shared.bytes, &kyber_shared.bytes, &context);
    Ok(HybridSession {
        session_key_b64: base64::engine::general_purpose::STANDARD.encode(session_key.as_slice()),
        encapsulated_key_b64: base64::engine::general_purpose::STANDARD.encode(encapsulated),
        metadata: SessionMetadata {
            algorithms: "x25519+kyber1024+hkdf-sha256",
        },
    })
}

pub fn zeroized_secret(bytes: Vec<u8>) -> SharedSecret {
    SharedSecret {
        bytes: Zeroizing::new(bytes),
    }
}

#[cfg(feature = "wasm")]
mod wasm_api {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn encrypt(plaintext: &[u8], dek: &[u8]) -> Result<JsValue, JsValue> {
        let envelope = encrypt_local(plaintext, dek).map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&envelope).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
