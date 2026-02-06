use axum::extract::{FromRef, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::q_core;
use crate::q_keygen;
use crate::signing;
use crate::pq;

use super::auth::{AuthConfig, AuthError, AuthUser};
use super::db::DbState;
use super::kms::{append_audit_log, generate_master_key, unwrap_key, wrap_key, KmsError, RootKey, TenantRecord};
use super::policy::{PolicyConfig, PolicyError};

#[derive(Clone, Debug)]
pub struct AppState {
    pub auth: AuthConfig,
    pub policy: PolicyConfig,
    pub db: DbState,
    pub root_key: RootKey,
}

impl FromRef<AppState> for AuthConfig {
    fn from_ref(input: &AppState) -> Self {
        input.auth.clone()
    }
}

impl FromRef<AppState> for PolicyConfig {
    fn from_ref(input: &AppState) -> Self {
        input.policy.clone()
    }
}

impl FromRef<AppState> for DbState {
    fn from_ref(input: &AppState) -> Self {
        input.db.clone()
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", axum::routing::get(health))
        .route("/v0/derive-key", axum::routing::post(derive_key))
        .route("/v0/encrypt", axum::routing::post(encrypt))
        .route("/v0/decrypt", axum::routing::post(decrypt))
        .route("/v0/sign", axum::routing::post(sign))
        .route("/v0/verify", axum::routing::post(verify))
        .route("/v1/kms/tenants", axum::routing::post(create_tenant))
        .route("/v1/kms/encrypt", axum::routing::post(kms_encrypt))
        .route("/v1/kms/decrypt", axum::routing::post(kms_decrypt))
        .route("/v1/kms/wrap-dek", axum::routing::post(kms_wrap_dek))
        .route("/v1/kms/unwrap-dek", axum::routing::post(kms_unwrap_dek))
        .route(
            "/v1/kms/rotate-master-key",
            axum::routing::post(rotate_master_key),
        )
        .route("/v1/kms/pq/keypair", axum::routing::post(kms_pq_keypair))
        .route("/v1/kms/pq/session", axum::routing::post(kms_pq_session))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

#[derive(Deserialize)]
struct DeriveKeyRequest {
    password: String,
    salt_phrase: Option<String>,
    device_fingerprint: Option<String>,
}

#[derive(Serialize)]
struct DeriveKeyResponse {
    key_b64: String,
    salt_b64: String,
}

async fn derive_key(
    State(_state): State<AppState>,
    _user: AuthUser,
    Json(payload): Json<DeriveKeyRequest>,
) -> Result<Json<DeriveKeyResponse>, ApiError> {
    let (key, salt) = q_keygen::derive_key_simple(
        &payload.password,
        payload.salt_phrase.as_deref(),
        payload.device_fingerprint.as_deref(),
    )
    .map_err(|err| ApiError::KeyGen(err.to_string()))?;

    Ok(Json(DeriveKeyResponse {
        key_b64: STANDARD.encode(key),
        salt_b64: STANDARD.encode(salt),
    }))
}

#[derive(Deserialize)]
struct EncryptRequest {
    plaintext_b64: String,
    key_b64: String,
    expires_in_seconds: Option<u64>,
}

#[derive(Serialize)]
struct EncryptResponse {
    ciphertext_b64: String,
    expires_at: Option<u64>,
}

async fn encrypt(
    State(_state): State<AppState>,
    _user: AuthUser,
    Json(payload): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, ApiError> {
    let key = STANDARD
        .decode(payload.key_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid key base64"))?;
    let plaintext = STANDARD
        .decode(payload.plaintext_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid plaintext base64"))?;

    let expires_at = payload
        .expires_in_seconds
        .map(|ttl| current_unix_timestamp() + ttl);
    let payload_bytes = pack_expiring_payload(&plaintext, expires_at);
    let ciphertext = q_core::encrypt_simple(&payload_bytes, &key)
        .map_err(|_| ApiError::Crypto("Encryption failed"))?;

    Ok(Json(EncryptResponse {
        ciphertext_b64: STANDARD.encode(ciphertext),
        expires_at,
    }))
}

#[derive(Deserialize)]
struct DecryptRequest {
    ciphertext_b64: String,
    key_b64: String,
}

#[derive(Serialize)]
struct DecryptResponse {
    plaintext_b64: String,
    expires_at: Option<u64>,
}

async fn decrypt(
    State(_state): State<AppState>,
    _user: AuthUser,
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, ApiError> {
    let key = STANDARD
        .decode(payload.key_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid key base64"))?;
    let ciphertext = STANDARD
        .decode(payload.ciphertext_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid ciphertext base64"))?;

    let payload_bytes = q_core::decrypt_simple(&ciphertext, &key)
        .map_err(|_| ApiError::Crypto("Decryption failed"))?;
    let (expires_at, plaintext) = unpack_expiring_payload(&payload_bytes)?;

    if let Some(expiry) = expires_at {
        if current_unix_timestamp() > expiry {
            return Err(ApiError::Expired);
        }
    }

    Ok(Json(DecryptResponse {
        plaintext_b64: STANDARD.encode(plaintext),
        expires_at,
    }))
}

#[derive(Deserialize)]
struct SignRequest {
    message_b64: String,
    secret_key_b64: String,
}

#[derive(Serialize)]
struct SignResponse {
    signature_b64: String,
}

async fn sign(
    State(_state): State<AppState>,
    _user: AuthUser,
    Json(payload): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    let message = STANDARD
        .decode(payload.message_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid message base64"))?;
    let secret_key = STANDARD
        .decode(payload.secret_key_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid secret key base64"))?;

    let signature = signing::sign_message_bytes(&secret_key, &message)
        .map_err(|_| ApiError::Crypto("Signing failed"))?;

    Ok(Json(SignResponse {
        signature_b64: STANDARD.encode(signature),
    }))
}

#[derive(Deserialize)]
struct VerifyRequest {
    message_b64: String,
    public_key_b64: String,
    signature_b64: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
}

async fn verify(
    State(_state): State<AppState>,
    _user: AuthUser,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let message = STANDARD
        .decode(payload.message_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid message base64"))?;
    let public_key = STANDARD
        .decode(payload.public_key_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid public key base64"))?;
    let signature = STANDARD
        .decode(payload.signature_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid signature base64"))?;

    let valid = signing::verify_signature_bytes(&public_key, &message, &signature)
        .map_err(|_| ApiError::Crypto("Verification failed"))?;

    Ok(Json(VerifyResponse { valid }))
}

#[derive(Deserialize)]
struct CreateTenantRequest {
    name: String,
}

#[derive(Serialize)]
struct CreateTenantResponse {
    tenant_id: String,
    name: String,
    key_version: u32,
    crypto_policy_version: u32,
    created_at: u64,
}

async fn create_tenant(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<CreateTenantRequest>,
) -> Result<Json<CreateTenantResponse>, ApiError> {
    require_scope(&user, "tenants:write")?;
    let mut master_key = generate_master_key();
    let wrapped_master_key = wrap_key(&master_key, state.root_key.expose())
        .map_err(|_| ApiError::Crypto("Tenant creation failed"))?;
    master_key.zeroize();
    let now = chrono::Utc::now().naive_utc();
    let tenant = TenantRecord {
        id: Uuid::new_v4(),
        name: payload.name,
        wrapped_master_key: wrapped_master_key.clone(),
        key_version: 1,
        crypto_policy_version: 1,
        created_at: now,
        updated_at: now,
    };
    state
        .db
        .insert_tenant(&tenant)
        .await
        .map_err(|_| ApiError::Crypto("Tenant creation failed"))?;
    state
        .db
        .insert_master_key_version(tenant.id, 1, &wrapped_master_key, now)
        .await
        .map_err(|_| ApiError::Crypto("Tenant creation failed"))?;
    Ok(Json(CreateTenantResponse {
        tenant_id: tenant.id.to_string(),
        name: tenant.name,
        key_version: tenant.key_version,
        crypto_policy_version: tenant.crypto_policy_version,
        created_at: tenant.created_at.and_utc().timestamp() as u64,
    }))
}

#[derive(Deserialize)]
struct KmsEncryptRequest {
    plaintext_b64: String,
}

#[derive(Serialize)]
struct KmsEncryptResponse {
    ciphertext_b64: String,
    wrapped_dek_b64: String,
    key_version: u32,
    nonce_b64: String,
    algorithm: String,
}

async fn kms_encrypt(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<KmsEncryptRequest>,
) -> Result<Json<KmsEncryptResponse>, ApiError> {
    require_scope(&user, "kms:encrypt")?;
    let tenant_id = extract_tenant_id(&headers, &user)?;
    let tenant = state
        .db
        .fetch_tenant(tenant_id)
        .await
        .map_err(|_| ApiError::Kms(KmsError::TenantNotFound))?;
    let master_version = state
        .db
        .fetch_master_key_version(tenant_id, tenant.key_version as i32)
        .await
        .map_err(|_| ApiError::Kms(KmsError::KeyVersionNotFound))?;
    let mut master_key = unwrap_key(&master_version.wrapped_master_key, state.root_key.expose())
        .map_err(|_| ApiError::Crypto("Master key unwrap failed"))?;
    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);
    let plaintext = STANDARD
        .decode(payload.plaintext_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid plaintext base64"))?;
    let (ciphertext, nonce) = encrypt_payload(&plaintext, &dek)
        .map_err(|_| ApiError::Crypto("Encryption failed"))?;
    let wrapped_dek = wrap_key(&dek, &master_key)
        .map_err(|_| ApiError::Crypto("DEK wrap failed"))?;
    let prev_hash = state
        .db
        .fetch_latest_audit_hash(tenant_id)
        .await
        .map_err(|_| ApiError::Crypto("Audit fetch failed"))?;
    let log_entry = append_audit_log(
        prev_hash,
        tenant_id,
        "encrypt",
        serde_json::json!({ "key_version": tenant.key_version }),
    );
    state
        .db
        .insert_audit_log(&log_entry)
        .await
        .map_err(|_| ApiError::Crypto("Audit write failed"))?;
    dek.zeroize();
    master_key.zeroize();
    Ok(Json(KmsEncryptResponse {
        ciphertext_b64: STANDARD.encode(ciphertext),
        wrapped_dek_b64: STANDARD.encode(wrapped_dek),
        key_version: tenant.key_version,
        nonce_b64: STANDARD.encode(nonce),
        algorithm: "chacha20poly1305".to_string(),
    }))
}

#[derive(Deserialize)]
struct KmsDecryptRequest {
    ciphertext_b64: String,
    wrapped_dek_b64: String,
    key_version: u32,
    nonce_b64: String,
    algorithm: String,
}

#[derive(Serialize)]
struct KmsDecryptResponse {
    plaintext_b64: String,
}

async fn kms_decrypt(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<KmsDecryptRequest>,
) -> Result<Json<KmsDecryptResponse>, ApiError> {
    require_scope(&user, "kms:decrypt")?;
    let tenant_id = extract_tenant_id(&headers, &user)?;
    let _tenant = state
        .db
        .fetch_tenant(tenant_id)
        .await
        .map_err(|_| ApiError::Kms(KmsError::TenantNotFound))?;
    let master_version = state
        .db
        .fetch_master_key_version(tenant_id, payload.key_version as i32)
        .await
        .map_err(|_| ApiError::Kms(KmsError::KeyVersionNotFound))?;
    let mut master_key = unwrap_key(&master_version.wrapped_master_key, state.root_key.expose())
        .map_err(|_| ApiError::Crypto("Master key unwrap failed"))?;
    let algorithm_ok = payload
        .algorithm
        .as_bytes()
        .ct_eq(b"chacha20poly1305")
        .unwrap_u8()
        == 1;
    if !algorithm_ok {
        return Err(ApiError::InvalidInput("Unsupported algorithm"));
    }
    let wrapped_dek = STANDARD
        .decode(payload.wrapped_dek_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid wrapped DEK base64"))?;
    let mut dek = unwrap_key(&wrapped_dek, &master_key)
        .map_err(|_| ApiError::Crypto("DEK unwrap failed"))?;
    let ciphertext = STANDARD
        .decode(payload.ciphertext_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid ciphertext base64"))?;
    let nonce = STANDARD
        .decode(payload.nonce_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid nonce base64"))?;
    let plaintext = decrypt_payload(&ciphertext, &nonce, &dek)
        .map_err(|_| ApiError::Crypto("Decryption failed"))?;
    dek.zeroize();
    master_key.zeroize();
    let prev_hash = state
        .db
        .fetch_latest_audit_hash(tenant_id)
        .await
        .map_err(|_| ApiError::Crypto("Audit fetch failed"))?;
    let log_entry = append_audit_log(
        prev_hash,
        tenant_id,
        "decrypt",
        serde_json::json!({ "key_version": payload.key_version }),
    );
    state
        .db
        .insert_audit_log(&log_entry)
        .await
        .map_err(|_| ApiError::Crypto("Audit write failed"))?;
    Ok(Json(KmsDecryptResponse {
        plaintext_b64: STANDARD.encode(plaintext),
    }))
}

#[derive(Deserialize)]
struct KmsWrapDekRequest {
    dek_b64: String,
}

#[derive(Serialize)]
struct KmsWrapDekResponse {
    wrapped_dek_b64: String,
    key_version: u32,
}

async fn kms_wrap_dek(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<KmsWrapDekRequest>,
) -> Result<Json<KmsWrapDekResponse>, ApiError> {
    require_scope(&user, "kms:encrypt")?;
    let tenant_id = extract_tenant_id(&headers, &user)?;
    let tenant = state
        .db
        .fetch_tenant(tenant_id)
        .await
        .map_err(|_| ApiError::Kms(KmsError::TenantNotFound))?;
    let master_version = state
        .db
        .fetch_master_key_version(tenant_id, tenant.key_version as i32)
        .await
        .map_err(|_| ApiError::Kms(KmsError::KeyVersionNotFound))?;
    let mut master_key = unwrap_key(&master_version.wrapped_master_key, state.root_key.expose())
        .map_err(|_| ApiError::Crypto("Master key unwrap failed"))?;
    let mut dek = STANDARD
        .decode(payload.dek_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid DEK base64"))?;
    let wrapped_dek = wrap_key(&dek, &master_key)
        .map_err(|_| ApiError::Crypto("DEK wrap failed"))?;
    dek.zeroize();
    master_key.zeroize();
    Ok(Json(KmsWrapDekResponse {
        wrapped_dek_b64: STANDARD.encode(wrapped_dek),
        key_version: tenant.key_version,
    }))
}

#[derive(Deserialize)]
struct KmsUnwrapDekRequest {
    wrapped_dek_b64: String,
    key_version: u32,
}

#[derive(Serialize)]
struct KmsUnwrapDekResponse {
    dek_b64: String,
}

async fn kms_unwrap_dek(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<KmsUnwrapDekRequest>,
) -> Result<Json<KmsUnwrapDekResponse>, ApiError> {
    require_scope(&user, "kms:decrypt")?;
    let tenant_id = extract_tenant_id(&headers, &user)?;
    let master_version = state
        .db
        .fetch_master_key_version(tenant_id, payload.key_version as i32)
        .await
        .map_err(|_| ApiError::Kms(KmsError::KeyVersionNotFound))?;
    let mut master_key = unwrap_key(&master_version.wrapped_master_key, state.root_key.expose())
        .map_err(|_| ApiError::Crypto("Master key unwrap failed"))?;
    let wrapped_dek = STANDARD
        .decode(payload.wrapped_dek_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid wrapped DEK base64"))?;
    let mut dek = unwrap_key(&wrapped_dek, &master_key)
        .map_err(|_| ApiError::Crypto("DEK unwrap failed"))?;
    master_key.zeroize();
    let dek_b64 = STANDARD.encode(&dek);
    dek.zeroize();
    Ok(Json(KmsUnwrapDekResponse { dek_b64 }))
}

#[derive(Serialize)]
struct RotateMasterKeyResponse {
    key_version: u32,
    rotated_at: u64,
}

async fn rotate_master_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Result<Json<RotateMasterKeyResponse>, ApiError> {
    require_scope(&user, "kms:rotate")?;
    let tenant_id = extract_tenant_id(&headers, &user)?;
    let tenant = state
        .db
        .fetch_tenant(tenant_id)
        .await
        .map_err(|_| ApiError::Kms(KmsError::TenantNotFound))?;
    let mut new_master_key = generate_master_key();
    let wrapped_master_key = wrap_key(&new_master_key, state.root_key.expose())
        .map_err(|_| ApiError::Crypto("Master key wrap failed"))?;
    new_master_key.zeroize();
    let next_version = tenant.key_version + 1;
    let now = chrono::Utc::now().naive_utc();
    state
        .db
        .insert_master_key_version(tenant_id, next_version as i32, &wrapped_master_key, now)
        .await
        .map_err(|_| ApiError::Crypto("Master key rotation failed"))?;
    state
        .db
        .update_tenant_key_version(tenant_id, next_version as i32, now)
        .await
        .map_err(|_| ApiError::Crypto("Master key rotation failed"))?;
    let prev_hash = state
        .db
        .fetch_latest_audit_hash(tenant_id)
        .await
        .map_err(|_| ApiError::Crypto("Audit fetch failed"))?;
    let log_entry = append_audit_log(
        prev_hash,
        tenant_id,
        "rotate_master_key",
        serde_json::json!({ "key_version": next_version }),
    );
    state
        .db
        .insert_audit_log(&log_entry)
        .await
        .map_err(|_| ApiError::Crypto("Audit write failed"))?;
    Ok(Json(RotateMasterKeyResponse {
        key_version: next_version,
        rotated_at: now.and_utc().timestamp() as u64,
    }))
}

#[derive(Deserialize)]
struct PqKeypairRequest {
    algorithm: Option<String>,
}

#[derive(Serialize)]
struct PqKeypairResponse {
    algorithm: String,
    version: u32,
    public_key_b64: String,
}

async fn kms_pq_keypair(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<PqKeypairRequest>,
) -> Result<Json<PqKeypairResponse>, ApiError> {
    require_scope(&user, "kms:pq:write")?;
    let tenant_id = extract_tenant_id(&headers, &user)?;
    let tenant = state
        .db
        .fetch_tenant(tenant_id)
        .await
        .map_err(|_| ApiError::Kms(KmsError::TenantNotFound))?;
    let algorithm = pq::PqAlgorithm::from_name(payload.algorithm.as_deref())
        .map_err(|_| ApiError::InvalidInput("Unsupported PQ algorithm"))?;
    let keypair = pq::keypair(algorithm);
    let master_version = state
        .db
        .fetch_master_key_version(tenant_id, tenant.key_version as i32)
        .await
        .map_err(|_| ApiError::Kms(KmsError::KeyVersionNotFound))?;
    let mut master_key = unwrap_key(&master_version.wrapped_master_key, state.root_key.expose())
        .map_err(|_| ApiError::Crypto("Master key unwrap failed"))?;
    let wrapped_private_key = wrap_key(&keypair.secret_key, &master_key)?;
    master_key.zeroize();
    let now = chrono::Utc::now().naive_utc();
    state
        .db
        .insert_pq_key(
            tenant_id,
            &keypair.algorithm.to_string(),
            &keypair.public_key,
            &wrapped_private_key,
            now,
        )
        .await
        .map_err(|_| ApiError::Crypto("PQ keypair storage failed"))?;
    let prev_hash = state
        .db
        .fetch_latest_audit_hash(tenant_id)
        .await
        .map_err(|_| ApiError::Crypto("Audit fetch failed"))?;
    let log_entry = append_audit_log(
        prev_hash,
        tenant_id,
        "pq_keypair",
        serde_json::json!({ "algorithm": keypair.algorithm.to_string() }),
    );
    state
        .db
        .insert_audit_log(&log_entry)
        .await
        .map_err(|_| ApiError::Crypto("Audit write failed"))?;
    Ok(Json(PqKeypairResponse {
        algorithm: keypair.algorithm.to_string(),
        version: tenant.key_version,
        public_key_b64: STANDARD.encode(keypair.public_key),
    }))
}

#[derive(Deserialize)]
struct PqSessionRequest {
    algorithm: Option<String>,
    client_x25519_public_key_b64: String,
    client_kyber_public_key_b64: String,
}

#[derive(Serialize)]
struct PqSessionResponse {
    algorithm: String,
    algorithm_id: String,
    version: u32,
    timestamp: u64,
    server_x25519_public_key_b64: String,
    kyber_ciphertext_b64: String,
    session_key_b64: String,
}

async fn kms_pq_session(
    State(_state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<PqSessionRequest>,
) -> Result<Json<PqSessionResponse>, ApiError> {
    require_scope(&user, "kms:pq:session")?;
    extract_tenant_id(&headers, &user)?;
    let algorithm = pq::PqAlgorithm::from_name(payload.algorithm.as_deref())
        .map_err(|_| ApiError::InvalidInput("Unsupported PQ algorithm"))?;
    let client_x25519_public = STANDARD
        .decode(payload.client_x25519_public_key_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid X25519 public key base64"))?;
    let client_kyber_public = STANDARD
        .decode(payload.client_kyber_public_key_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid Kyber public key base64"))?;
    let (server_public, session_key, ciphertext) =
        pq::hybrid_session(algorithm, &client_x25519_public, &client_kyber_public)
            .map_err(|_| ApiError::Crypto("Hybrid session failed"))?;
    let now = chrono::Utc::now().timestamp() as u64;
    Ok(Json(PqSessionResponse {
        algorithm: algorithm.to_string(),
        algorithm_id: algorithm.algorithm_id().to_string(),
        version: 1,
        timestamp: now,
        server_x25519_public_key_b64: STANDARD.encode(server_public),
        kyber_ciphertext_b64: STANDARD.encode(ciphertext),
        session_key_b64: STANDARD.encode(session_key),
    }))
}

fn pack_expiring_payload(message: &[u8], expires_at: Option<u64>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + message.len());
    let expiry = expires_at.unwrap_or(0).to_be_bytes();
    payload.extend_from_slice(&expiry);
    payload.extend_from_slice(message);
    payload
}

fn unpack_expiring_payload(payload: &[u8]) -> Result<(Option<u64>, Vec<u8>), ApiError> {
    if payload.len() < 8 {
        return Err(ApiError::InvalidInput("Invalid payload length"));
    }
    let (expiry_bytes, message) = payload.split_at(8);
    let expiry = u64::from_be_bytes(expiry_bytes.try_into().unwrap());
    let expires_at = if expiry == 0 { None } else { Some(expiry) };
    Ok((expires_at, message.to_vec()))
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

#[derive(Debug)]
pub enum ApiError {
    InvalidInput(&'static str),
    Crypto(&'static str),
    KeyGen(String),
    Auth(AuthError),
    Policy(PolicyError),
    Kms(KmsError),
    Expired,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Crypto(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::KeyGen(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Key derivation failed"),
            ApiError::Auth(_) => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            ApiError::Policy(_) => (StatusCode::FORBIDDEN, "Request blocked by policy"),
            ApiError::Kms(err) => match err {
                KmsError::TenantNotFound => (StatusCode::NOT_FOUND, "Tenant not found"),
                KmsError::KeyVersionNotFound => (StatusCode::NOT_FOUND, "Key version not found"),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "KMS error"),
            },
            ApiError::Expired => (StatusCode::GONE, "Ciphertext expired"),
        };
        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        ApiError::Auth(err)
    }
}

impl From<PolicyError> for ApiError {
    fn from(err: PolicyError) -> Self {
        ApiError::Policy(err)
    }
}

impl From<KmsError> for ApiError {
    fn from(err: KmsError) -> Self {
        ApiError::Kms(err)
    }
}

fn extract_tenant_id(headers: &HeaderMap, user: &AuthUser) -> Result<Uuid, ApiError> {
    let header_value = headers
        .get("x-tenant-id")
        .ok_or(ApiError::Auth(AuthError::MissingAuthorization))?
        .to_str()
        .map_err(|_| ApiError::InvalidInput("Invalid tenant header"))?;
    let tenant_id = Uuid::parse_str(header_value)
        .map_err(|_| ApiError::InvalidInput("Invalid tenant id"))?;
    let user_tenant = user
        .tenant_id
        .as_ref()
        .ok_or(ApiError::Auth(AuthError::InvalidToken))?;
    let user_tenant_id =
        Uuid::parse_str(user_tenant).map_err(|_| ApiError::InvalidInput("Invalid tenant id"))?;
    if tenant_id.as_bytes().ct_eq(user_tenant_id.as_bytes()).unwrap_u8() != 1 {
        return Err(ApiError::Auth(AuthError::InvalidToken));
    }
    Ok(tenant_id)
}

fn require_scope(user: &AuthUser, scope: &str) -> Result<(), ApiError> {
    if user.scopes.iter().any(|value| value == scope) {
        Ok(())
    } else {
        Err(ApiError::Policy(PolicyError::Forbidden))
    }
}

fn encrypt_payload(plaintext: &[u8], dek: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ApiError> {
    let cipher = ChaCha20Poly1305::new_from_slice(dek)
        .map_err(|_| ApiError::Crypto("Encryption failed"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ApiError::Crypto("Encryption failed"))?;
    Ok((ciphertext, nonce_bytes.to_vec()))
}

fn decrypt_payload(ciphertext: &[u8], nonce_bytes: &[u8], dek: &[u8]) -> Result<Vec<u8>, ApiError> {
    let cipher = ChaCha20Poly1305::new_from_slice(dek)
        .map_err(|_| ApiError::Crypto("Decryption failed"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ApiError::Crypto("Decryption failed"))
}
