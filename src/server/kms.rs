use std::collections::HashMap;
use std::env;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

#[derive(Clone)]
pub struct KmsState {
    root_key: Arc<RootKey>,
    tenants: Arc<RwLock<HashMap<Uuid, TenantRecord>>>,
}

impl std::fmt::Debug for KmsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KmsState")
            .field("tenants", &"<redacted>")
            .finish()
    }
}

impl KmsState {
    pub fn from_env() -> Result<Self, KmsError> {
        Ok(Self {
            root_key: Arc::new(RootKey::from_env()?),
            tenants: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn root_key(&self) -> Arc<RootKey> {
        self.root_key.clone()
    }

    pub fn create_tenant(&self, name: String) -> Result<TenantRecord, KmsError> {
        let tenant_id = Uuid::new_v4();
        let mut master_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut master_key);
        let wrapped_master_key =
            wrap_key(&master_key, self.root_key.expose()).map_err(|_| KmsError::CryptoError)?;
        master_key.zeroize();
        let now = current_timestamp();
        let record = TenantRecord {
            id: tenant_id,
            name,
            wrapped_master_keys: HashMap::from([(1, wrapped_master_key)]),
            key_version: 1,
            crypto_policy_version: 1,
            pq_keys: Vec::new(),
            audit_logs: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        let mut tenants = self.tenants.write().expect("tenant lock poisoned");
        tenants.insert(tenant_id, record.clone());
        Ok(record)
    }

    pub fn get_tenant(&self, tenant_id: Uuid) -> Result<TenantRecord, KmsError> {
        let tenants = self.tenants.read().expect("tenant lock poisoned");
        tenants
            .get(&tenant_id)
            .cloned()
            .ok_or(KmsError::TenantNotFound)
    }

    pub fn update_tenant(&self, tenant: TenantRecord) -> Result<(), KmsError> {
        let mut tenants = self.tenants.write().expect("tenant lock poisoned");
        tenants.insert(tenant.id, tenant);
        Ok(())
    }

    pub fn rotate_master_key(&self, tenant_id: Uuid) -> Result<TenantRecord, KmsError> {
        let mut tenants = self.tenants.write().expect("tenant lock poisoned");
        let tenant = tenants.get_mut(&tenant_id).ok_or(KmsError::TenantNotFound)?;
        let mut new_master_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_master_key);
        let wrapped_master_key =
            wrap_key(&new_master_key, self.root_key.expose()).map_err(|_| KmsError::CryptoError)?;
        new_master_key.zeroize();
        tenant.key_version += 1;
        tenant
            .wrapped_master_keys
            .insert(tenant.key_version, wrapped_master_key);
        tenant.updated_at = current_timestamp();
        Ok(tenant.clone())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TenantRecord {
    pub id: Uuid,
    pub name: String,
    pub wrapped_master_keys: HashMap<u32, Vec<u8>>,
    pub key_version: u32,
    pub crypto_policy_version: u32,
    pub pq_keys: Vec<PqKeyRecord>,
    pub audit_logs: Vec<AuditLog>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PqKeyRecord {
    pub version: u32,
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub wrapped_private_key: Vec<u8>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub event_type: String,
    pub event_hash: Vec<u8>,
    pub prev_hash: Option<Vec<u8>>,
    pub metadata: serde_json::Value,
    pub created_at: u64,
}

pub fn wrap_key(key: &[u8], wrapping_key: &[u8]) -> Result<Vec<u8>, KmsError> {
    q_core::encrypt_simple(key, wrapping_key).map_err(|_| KmsError::CryptoError)
}

pub fn unwrap_key(wrapped: &[u8], wrapping_key: &[u8]) -> Result<Vec<u8>, KmsError> {
    q_core::decrypt_simple(wrapped, wrapping_key).map_err(|_| KmsError::CryptoError)
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn append_audit_log(
    tenant: &mut TenantRecord,
    event_type: &str,
    metadata: serde_json::Value,
) {
    let prev_hash = tenant
        .audit_logs
        .last()
        .map(|entry| entry.event_hash.clone());
    let event_payload = serde_json::json!({
        "tenant_id": tenant.id,
        "event_type": event_type,
        "metadata": metadata,
        "prev_hash": prev_hash,
    });
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&event_payload).unwrap_or_default());
    let event_hash = hasher.finalize().to_vec();
    tenant.audit_logs.push(AuditLog {
        id: Uuid::new_v4(),
        tenant_id: tenant.id,
        event_type: event_type.to_string(),
        event_hash,
        prev_hash,
        metadata,
        created_at: current_timestamp(),
    });
}
