use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::env;
use zeroize::ZeroizeOnDrop;

use uuid::Uuid;

use crate::q_core;

#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    #[error("missing root key env var")]
    MissingRootKey,
    #[error("invalid root key")]
    InvalidRootKey,
    #[error("tenant not found")]
    TenantNotFound,
    #[error("key version not found")]
    KeyVersionNotFound,
    #[error("crypto error")]
    CryptoError,
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct RootKey {
    bytes: [u8; 32],
}

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootKey").field("bytes", &"<redacted>").finish()
    }
}

impl RootKey {
    pub fn from_env() -> Result<Self, KmsError> {
        let value = env::var("QIMEM_ROOT_KEY_B64").map_err(|_| KmsError::MissingRootKey)?;
        let decoded = STANDARD
            .decode(value)
            .map_err(|_| KmsError::InvalidRootKey)?;
        if decoded.len() != 32 {
            return Err(KmsError::InvalidRootKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded);
        Ok(Self { bytes })
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[derive(Clone, Debug)]
pub struct TenantRecord {
    pub id: Uuid,
    pub name: String,
    pub wrapped_master_key: Vec<u8>,
    pub key_version: u32,
    pub crypto_policy_version: u32,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Clone, Debug)]
pub struct TenantKeyVersion {
    pub tenant_id: Uuid,
    pub version: u32,
    pub wrapped_master_key: Vec<u8>,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub event_type: String,
    pub event_hash: Vec<u8>,
    pub prev_hash: Option<Vec<u8>>,
    pub metadata: serde_json::Value,
    pub created_at: chrono::NaiveDateTime,
}

pub fn wrap_key(key: &[u8], wrapping_key: &[u8]) -> Result<Vec<u8>, KmsError> {
    q_core::encrypt_simple(key, wrapping_key).map_err(|_| KmsError::CryptoError)
}

pub fn unwrap_key(wrapped: &[u8], wrapping_key: &[u8]) -> Result<Vec<u8>, KmsError> {
    q_core::decrypt_simple(wrapped, wrapping_key).map_err(|_| KmsError::CryptoError)
}

pub fn generate_master_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub fn append_audit_log(
    prev_hash: Option<Vec<u8>>,
    tenant_id: Uuid,
    event_type: &str,
    metadata: serde_json::Value,
) -> AuditLogEntry {
    let event_payload = serde_json::json!({
        "tenant_id": tenant_id,
        "event_type": event_type,
        "metadata": metadata,
        "prev_hash": prev_hash,
    });
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&event_payload).unwrap_or_default());
    let event_hash = hasher.finalize().to_vec();
    AuditLogEntry {
        id: Uuid::new_v4(),
        tenant_id,
        event_type: event_type.to_string(),
        event_hash,
        prev_hash,
        metadata,
        created_at: chrono::Utc::now().naive_utc(),
    }
}
