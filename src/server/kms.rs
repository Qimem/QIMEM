use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::env;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;
use zeroize::{Zeroize, Zeroizing};

use uuid::Uuid;

use crate::q_core;
use crate::server::db::DbState;

#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    #[error("missing root key env var")]
    MissingRootKey,
    #[error("invalid root key")]
    InvalidRootKey,
    #[error("unsupported root key source")]
    UnsupportedRootKeySource,
    #[error("invalid input")]
    InvalidInput,
    #[error("unsupported algorithm")]
    InvalidAlgorithm,
    #[error("tenant not found")]
    TenantNotFound,
    #[error("key version not found")]
    KeyVersionNotFound,
    #[error("crypto error")]
    CryptoError,
    #[error("root rotation not enabled")]
    RotationNotEnabled,
    #[error("root rotation confirmation missing")]
    RotationConfirmationMissing,
}

#[derive(Clone, Copy, Debug)]
pub enum RootKeySource {
    Env,
    SecretManager,
}

impl RootKeySource {
    pub fn from_env() -> Result<Self, KmsError> {
        let source = env::var("QIMEM_ROOT_KEY_SOURCE").unwrap_or_else(|_| "env".to_string());
        match source.as_str() {
            "env" => Ok(RootKeySource::Env),
            "secret-manager" => Ok(RootKeySource::SecretManager),
            _ => Err(KmsError::UnsupportedRootKeySource),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RootKeyConfig {
    pub source: RootKeySource,
}

#[derive(Clone, ZeroizeOnDrop)]
struct RootKey {
    bytes: [u8; 32],
}

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootKey").field("bytes", &"<redacted>").finish()
    }
}

impl RootKey {
    fn load(config: RootKeyConfig) -> Result<Self, KmsError> {
        match config.source {
            RootKeySource::Env => Self::from_env(),
            RootKeySource::SecretManager => Err(KmsError::UnsupportedRootKeySource),
        }
    }

    fn from_env() -> Result<Self, KmsError> {
        let value = env::var("QIMEM_ROOT_KEY_B64").map_err(|_| KmsError::MissingRootKey)?;
        Self::from_env_override(&value)
    }

    fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }

    fn from_env_override(value: &str) -> Result<Self, KmsError> {
        let decoded = Zeroizing::new(
            STANDARD
                .decode(value)
                .map_err(|_| KmsError::InvalidRootKey)?,
        );
        if decoded.len() != 32 {
            return Err(KmsError::InvalidRootKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded);
        Ok(Self { bytes })
    }
}

#[derive(Clone, Debug)]
pub struct KmsService {
    db: DbState,
    root_key: RootKey,
}

impl KmsService {
    pub async fn from_env() -> Result<Self, KmsError> {
        let source = RootKeySource::from_env()?;
        let root_key = RootKey::load(RootKeyConfig { source })?;
        let database_url = env::var("QIMEM_DATABASE_URL").map_err(|_| KmsError::CryptoError)?;
        let db = DbState::connect(&database_url)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        Ok(Self { db, root_key })
    }

    pub fn new_with_root_key(db: DbState, root_key_b64: &str) -> Result<Self, KmsError> {
        let root_key = RootKey::from_env_override(root_key_b64)?;
        Ok(Self { db, root_key })
    }

    pub fn db(&self) -> &DbState {
        &self.db
    }

    pub fn root_key_source() -> Result<RootKeySource, KmsError> {
        RootKeySource::from_env()
    }

    pub async fn create_tenant(&self, name: String) -> Result<TenantRecord, KmsError> {
        let mut master_key = generate_master_key();
        let wrapped_master_key = wrap_key(&master_key, self.root_key.expose())?;
        master_key.zeroize();
        let now = chrono::Utc::now().naive_utc();
        let tenant = TenantRecord {
            id: Uuid::new_v4(),
            name,
            wrapped_master_key: wrapped_master_key.clone(),
            key_version: 1,
            crypto_policy_version: 1,
            created_at: now,
            updated_at: now,
        };
        self.db
            .insert_tenant(&tenant)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        self.db
            .insert_master_key_version(tenant.id, 1, &wrapped_master_key, now)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        Ok(tenant)
    }

    pub async fn encrypt(
        &self,
        tenant_id: Uuid,
        plaintext_b64: String,
    ) -> Result<EncryptResponse, KmsError> {
        let tenant = self
            .db
            .fetch_tenant(tenant_id)
            .await
            .map_err(|_| KmsError::TenantNotFound)?;
        let master_version = self
            .db
            .fetch_master_key_version(tenant_id, tenant.key_version as i32)
            .await
            .map_err(|_| KmsError::KeyVersionNotFound)?;
        let mut master_key = unwrap_key(&master_version.wrapped_master_key, self.root_key.expose())?;
        let mut dek = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut dek);
        let plaintext = STANDARD
            .decode(plaintext_b64)
            .map_err(|_| KmsError::InvalidInput)?;
        let (ciphertext, nonce) = encrypt_payload(&plaintext, &dek)?;
        let wrapped_dek = wrap_key(&dek, &master_key)?;
        let prev_hash = self
            .db
            .fetch_latest_audit_hash(tenant_id)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        let log_entry = append_audit_log(
            prev_hash,
            tenant_id,
            "encrypt",
            serde_json::json!({ "key_version": tenant.key_version }),
        );
        self.db
            .insert_audit_log(&log_entry)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        dek.zeroize();
        master_key.zeroize();
        Ok(EncryptResponse {
            ciphertext_b64: STANDARD.encode(ciphertext),
            wrapped_dek_b64: STANDARD.encode(wrapped_dek),
            key_version: tenant.key_version,
            nonce_b64: STANDARD.encode(nonce),
            algorithm: "chacha20poly1305".to_string(),
        })
    }

    pub async fn decrypt(
        &self,
        tenant_id: Uuid,
        request: DecryptRequest,
    ) -> Result<Vec<u8>, KmsError> {
        let _tenant = self
            .db
            .fetch_tenant(tenant_id)
            .await
            .map_err(|_| KmsError::TenantNotFound)?;
        let master_version = self
            .db
            .fetch_master_key_version(tenant_id, request.key_version as i32)
            .await
            .map_err(|_| KmsError::KeyVersionNotFound)?;
        let mut master_key = unwrap_key(&master_version.wrapped_master_key, self.root_key.expose())?;
        let algorithm_ok = request
            .algorithm
            .as_bytes()
            .ct_eq(b"chacha20poly1305")
            .unwrap_u8()
            == 1;
        if !algorithm_ok {
            return Err(KmsError::InvalidAlgorithm);
        }
        let wrapped_dek = STANDARD
            .decode(request.wrapped_dek_b64)
            .map_err(|_| KmsError::InvalidInput)?;
        let mut dek = unwrap_key(&wrapped_dek, &master_key)?;
        let ciphertext = STANDARD
            .decode(request.ciphertext_b64)
            .map_err(|_| KmsError::InvalidInput)?;
        let nonce = STANDARD
            .decode(request.nonce_b64)
            .map_err(|_| KmsError::InvalidInput)?;
        let plaintext = decrypt_payload(&ciphertext, &nonce, &dek)?;
        dek.zeroize();
        master_key.zeroize();
        let prev_hash = self
            .db
            .fetch_latest_audit_hash(tenant_id)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        let log_entry = append_audit_log(
            prev_hash,
            tenant_id,
            "decrypt",
            serde_json::json!({ "key_version": request.key_version }),
        );
        self.db
            .insert_audit_log(&log_entry)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        Ok(plaintext)
    }

    pub async fn wrap_dek(&self, tenant_id: Uuid, dek_b64: String) -> Result<WrapDekResponse, KmsError> {
        let tenant = self
            .db
            .fetch_tenant(tenant_id)
            .await
            .map_err(|_| KmsError::TenantNotFound)?;
        let master_version = self
            .db
            .fetch_master_key_version(tenant_id, tenant.key_version as i32)
            .await
            .map_err(|_| KmsError::KeyVersionNotFound)?;
        let mut master_key = unwrap_key(&master_version.wrapped_master_key, self.root_key.expose())?;
        let mut dek = STANDARD
            .decode(dek_b64)
            .map_err(|_| KmsError::InvalidInput)?;
        let wrapped_dek = wrap_key(&dek, &master_key)?;
        dek.zeroize();
        master_key.zeroize();
        Ok(WrapDekResponse {
            wrapped_dek_b64: STANDARD.encode(wrapped_dek),
            key_version: tenant.key_version,
        })
    }

    pub async fn unwrap_dek(
        &self,
        tenant_id: Uuid,
        wrapped_dek_b64: String,
        key_version: u32,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        let _tenant = self
            .db
            .fetch_tenant(tenant_id)
            .await
            .map_err(|_| KmsError::TenantNotFound)?;
        let master_version = self
            .db
            .fetch_master_key_version(tenant_id, key_version as i32)
            .await
            .map_err(|_| KmsError::KeyVersionNotFound)?;
        let mut master_key = unwrap_key(&master_version.wrapped_master_key, self.root_key.expose())?;
        let wrapped_dek = STANDARD
            .decode(wrapped_dek_b64)
            .map_err(|_| KmsError::InvalidInput)?;
        let dek = unwrap_key(&wrapped_dek, &master_key)?;
        master_key.zeroize();
        Ok(Zeroizing::new(dek))
    }

    pub async fn rotate_master_key(&self, tenant_id: Uuid) -> Result<RotateMasterKeyResponse, KmsError> {
        let tenant = self
            .db
            .fetch_tenant(tenant_id)
            .await
            .map_err(|_| KmsError::TenantNotFound)?;
        let mut new_master_key = generate_master_key();
        let wrapped_master_key = wrap_key(&new_master_key, self.root_key.expose())?;
        new_master_key.zeroize();
        let next_version = tenant.key_version + 1;
        let now = chrono::Utc::now().naive_utc();
        self.db
            .insert_master_key_version(tenant_id, next_version as i32, &wrapped_master_key, now)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        self.db
            .update_tenant_key_version(tenant_id, next_version as i32, now)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        let prev_hash = self
            .db
            .fetch_latest_audit_hash(tenant_id)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        let log_entry = append_audit_log(
            prev_hash,
            tenant_id,
            "rotate_master_key",
            serde_json::json!({ "key_version": next_version }),
        );
        self.db
            .insert_audit_log(&log_entry)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        Ok(RotateMasterKeyResponse {
            key_version: next_version,
            rotated_at: now,
        })
    }

    pub async fn list_audit_logs(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditLogEntry>, KmsError> {
        self.db
            .fetch_audit_logs(tenant_id, limit)
            .await
            .map_err(|_| KmsError::CryptoError)
    }

    pub async fn store_pq_keypair(
        &self,
        tenant_id: Uuid,
        algorithm: &str,
        public_key: &[u8],
        secret_key: &[u8],
    ) -> Result<(), KmsError> {
        let tenant = self
            .db
            .fetch_tenant(tenant_id)
            .await
            .map_err(|_| KmsError::TenantNotFound)?;
        let master_version = self
            .db
            .fetch_master_key_version(tenant_id, tenant.key_version as i32)
            .await
            .map_err(|_| KmsError::KeyVersionNotFound)?;
        let mut master_key = unwrap_key(&master_version.wrapped_master_key, self.root_key.expose())?;
        let wrapped_private_key = wrap_key(secret_key, &master_key)?;
        master_key.zeroize();
        let now = chrono::Utc::now().naive_utc();
        self.db
            .insert_pq_key(tenant_id, algorithm, public_key, &wrapped_private_key, now)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        let prev_hash = self
            .db
            .fetch_latest_audit_hash(tenant_id)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        let log_entry = append_audit_log(
            prev_hash,
            tenant_id,
            "pq_keypair",
            serde_json::json!({ "algorithm": algorithm }),
        );
        self.db
            .insert_audit_log(&log_entry)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        Ok(())
    }

    pub async fn log_gateway_decrypt(&self, tenant_id: Uuid, metadata: serde_json::Value) -> Result<(), KmsError> {
        let prev_hash = self
            .db
            .fetch_latest_audit_hash(tenant_id)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        let log_entry = append_audit_log(prev_hash, tenant_id, "decrypt", metadata);
        self.db
            .insert_audit_log(&log_entry)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        Ok(())
    }

    pub async fn decrypt_for_gateway(
        &self,
        tenant_id: Uuid,
        wrapped_dek_b64: String,
        ciphertext_b64: String,
        nonce_b64: String,
        algorithm: String,
        key_version: u32,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        let _tenant = self
            .db
            .fetch_tenant(tenant_id)
            .await
            .map_err(|_| KmsError::TenantNotFound)?;
        let master_version = self
            .db
            .fetch_master_key_version(tenant_id, key_version as i32)
            .await
            .map_err(|_| KmsError::KeyVersionNotFound)?;
        let mut master_key = unwrap_key(&master_version.wrapped_master_key, self.root_key.expose())?;
        let algorithm_ok = algorithm.as_bytes().ct_eq(b"chacha20poly1305").unwrap_u8() == 1;
        if !algorithm_ok {
            return Err(KmsError::InvalidAlgorithm);
        }
        let wrapped_dek = STANDARD.decode(wrapped_dek_b64).map_err(|_| KmsError::InvalidInput)?;
        let mut dek = unwrap_key(&wrapped_dek, &master_key)?;
        let ciphertext = STANDARD.decode(ciphertext_b64).map_err(|_| KmsError::InvalidInput)?;
        let nonce = STANDARD.decode(nonce_b64).map_err(|_| KmsError::InvalidInput)?;
        let plaintext = decrypt_payload(&ciphertext, &nonce, &dek)?;
        dek.zeroize();
        master_key.zeroize();
        Ok(Zeroizing::new(plaintext))
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

#[derive(Debug)]
pub struct EncryptResponse {
    pub ciphertext_b64: String,
    pub wrapped_dek_b64: String,
    pub key_version: u32,
    pub nonce_b64: String,
    pub algorithm: String,
}

#[derive(Debug)]
pub struct DecryptRequest {
    pub ciphertext_b64: String,
    pub wrapped_dek_b64: String,
    pub key_version: u32,
    pub nonce_b64: String,
    pub algorithm: String,
}

#[derive(Debug)]
pub struct WrapDekResponse {
    pub wrapped_dek_b64: String,
    pub key_version: u32,
}

#[derive(Debug)]
pub struct RotateMasterKeyResponse {
    pub key_version: u32,
    pub rotated_at: chrono::NaiveDateTime,
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

pub struct RootRotationOptions {
    pub dry_run: bool,
    pub enable_destructive: bool,
    pub confirmation: String,
}

#[derive(Debug)]
pub struct RootRotationSummary {
    pub rotation_id: Uuid,
    pub tenant_count: usize,
    pub dry_run: bool,
}

pub async fn rotate_root_key(options: RootRotationOptions) -> Result<RootRotationSummary, KmsError> {
    if !options.enable_destructive {
        return Err(KmsError::RotationNotEnabled);
    }
    if options.confirmation != "CONFIRM_ROOT_ROTATION_AND_DATA_REENCRYPTION" {
        return Err(KmsError::RotationConfirmationMissing);
    }
    let source = RootKeySource::from_env()?;
    let old_root = RootKey::load(RootKeyConfig { source })?;
    let new_root_b64 = env::var("QIMEM_NEW_ROOT_KEY_B64").map_err(|_| KmsError::MissingRootKey)?;
    let new_root = RootKey::from_env_override(&new_root_b64)?;
    let database_url = env::var("QIMEM_DATABASE_URL").map_err(|_| KmsError::CryptoError)?;
    let db = DbState::connect(&database_url)
        .await
        .map_err(|_| KmsError::CryptoError)?;
    let versions = db
        .fetch_all_master_key_versions()
        .await
        .map_err(|_| KmsError::CryptoError)?;
    let mut tenant_ids = std::collections::HashSet::new();
    for version in &versions {
        tenant_ids.insert(version.tenant_id);
    }
    let started_at = chrono::Utc::now().naive_utc();
    let rotation_id = Uuid::new_v4();
    if options.dry_run {
        db.insert_root_key_rotation(
            rotation_id,
            started_at,
            Some(started_at),
            tenant_ids.len() as i32,
            true,
        )
        .await
        .map_err(|_| KmsError::CryptoError)?;
        return Ok(RootRotationSummary {
            rotation_id,
            tenant_count: tenant_ids.len(),
            dry_run: true,
        });
    }

    for tenant_id in &tenant_ids {
        let prev_hash = db
            .fetch_latest_audit_hash(*tenant_id)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        let log_entry = append_audit_log(
            prev_hash,
            *tenant_id,
            "root_rotation_start",
            serde_json::json!({ "rotation_id": rotation_id }),
        );
        db.insert_audit_log(&log_entry)
            .await
            .map_err(|_| KmsError::CryptoError)?;
    }

    for version in versions {
        let mut master_key = unwrap_key(&version.wrapped_master_key, old_root.expose())?;
        let wrapped_new = wrap_key(&master_key, new_root.expose())?;
        master_key.zeroize();
        db.update_master_key_version(version.tenant_id, version.version as i32, &wrapped_new)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        db.update_tenant_wrapped_master_key_for_version(
            version.tenant_id,
            version.version as i32,
            &wrapped_new,
        )
        .await
        .map_err(|_| KmsError::CryptoError)?;
    }

    for tenant_id in &tenant_ids {
        let prev_hash = db
            .fetch_latest_audit_hash(*tenant_id)
            .await
            .map_err(|_| KmsError::CryptoError)?;
        let log_entry = append_audit_log(
            prev_hash,
            *tenant_id,
            "root_rotation_complete",
            serde_json::json!({ "rotation_id": rotation_id }),
        );
        db.insert_audit_log(&log_entry)
            .await
            .map_err(|_| KmsError::CryptoError)?;
    }

    let completed_at = chrono::Utc::now().naive_utc();
    db.insert_root_key_rotation(
        rotation_id,
        started_at,
        Some(completed_at),
        tenant_ids.len() as i32,
        false,
    )
    .await
    .map_err(|_| KmsError::CryptoError)?;

    Ok(RootRotationSummary {
        rotation_id,
        tenant_count: tenant_ids.len(),
        dry_run: false,
    })
}

fn encrypt_payload(plaintext: &[u8], dek: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KmsError> {
    let cipher = ChaCha20Poly1305::new_from_slice(dek).map_err(|_| KmsError::CryptoError)?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| KmsError::CryptoError)?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

fn decrypt_payload(ciphertext: &[u8], nonce_bytes: &[u8], dek: &[u8]) -> Result<Vec<u8>, KmsError> {
    let cipher = ChaCha20Poly1305::new_from_slice(dek).map_err(|_| KmsError::CryptoError)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| KmsError::CryptoError)
}
