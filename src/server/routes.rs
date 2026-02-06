use axum::extract::{FromRef, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::q_core;
use crate::q_keygen;
use crate::signing;
use crate::pq;

use super::auth::{AuthConfig, AuthError, AuthUser};
use super::kms::{DecryptRequest as KmsDecryptPayload, KmsError, KmsService};
use super::policy::{PolicyConfig, PolicyError};

#[derive(Clone, Debug)]
pub struct AppState {
    pub auth: AuthConfig,
    pub policy: PolicyConfig,
    pub kms: KmsService,
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

impl FromRef<AppState> for KmsService {
    fn from_ref(input: &AppState) -> Self {
        input.kms.clone()
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
        .route("/v1/kms/sign", axum::routing::post(kms_sign))
        .route("/v1/kms/verify", axum::routing::post(kms_verify))
        .route("/v1/kms/audit", axum::routing::get(kms_audit_logs))
        .route("/v1/kms/pq/keypair", axum::routing::post(kms_pq_keypair))
        .route("/v1/kms/pq/x25519", axum::routing::post(kms_pq_x25519))
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
    let tenant = state
        .kms
        .create_tenant(payload.name)
        .await
        .map_err(ApiError::from)?;
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
    let response = state
        .kms
        .encrypt(tenant_id, payload.plaintext_b64)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(KmsEncryptResponse {
        ciphertext_b64: response.ciphertext_b64,
        wrapped_dek_b64: response.wrapped_dek_b64,
        key_version: response.key_version,
        nonce_b64: response.nonce_b64,
        algorithm: response.algorithm,
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
    let plaintext = state
        .kms
        .decrypt(
            tenant_id,
            KmsDecryptPayload {
                ciphertext_b64: payload.ciphertext_b64,
                wrapped_dek_b64: payload.wrapped_dek_b64,
                key_version: payload.key_version,
                nonce_b64: payload.nonce_b64,
                algorithm: payload.algorithm,
            },
        )
        .await
        .map_err(ApiError::from)?;
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
    let response = state
        .kms
        .wrap_dek(tenant_id, payload.dek_b64)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(KmsWrapDekResponse {
        wrapped_dek_b64: response.wrapped_dek_b64,
        key_version: response.key_version,
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
    let dek = state
        .kms
        .unwrap_dek(tenant_id, payload.wrapped_dek_b64, payload.key_version)
        .await
        .map_err(ApiError::from)?;
    let dek_b64 = STANDARD.encode(&dek);
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
    let response = state.kms.rotate_master_key(tenant_id).await.map_err(ApiError::from)?;
    Ok(Json(RotateMasterKeyResponse {
        key_version: response.key_version,
        rotated_at: response.rotated_at.and_utc().timestamp() as u64,
    }))
}

#[derive(Deserialize)]
struct KmsSignRequest {
    message_b64: String,
    secret_key_b64: Option<String>,
}

#[derive(Serialize)]
struct KmsSignResponse {
    signature_b64: String,
    public_key_b64: String,
}

async fn kms_sign(
    State(_state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<KmsSignRequest>,
) -> Result<Json<KmsSignResponse>, ApiError> {
    require_scope(&user, "kms:sign")?;
    extract_tenant_id(&headers, &user)?;
    let message = STANDARD
        .decode(payload.message_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid message base64"))?;
    let (public_key, secret_key) = match payload.secret_key_b64 {
        Some(secret_key_b64) => {
            let secret_key = STANDARD
                .decode(secret_key_b64)
                .map_err(|_| ApiError::InvalidInput("Invalid secret key base64"))?;
            let public_key = signing::public_key_from_secret(&secret_key)
                .map_err(|_| ApiError::InvalidInput("Invalid secret key"))?;
            (public_key, secret_key)
        }
        None => signing::generate_keypair_bytes(),
    };
    let signature = signing::sign_message_bytes(&secret_key, &message)
        .map_err(|_| ApiError::Crypto("Signing failed"))?;
    Ok(Json(KmsSignResponse {
        signature_b64: STANDARD.encode(signature),
        public_key_b64: STANDARD.encode(public_key),
    }))
}

#[derive(Deserialize)]
struct KmsVerifyRequest {
    message_b64: String,
    public_key_b64: String,
    signature_b64: String,
}

#[derive(Serialize)]
struct KmsVerifyResponse {
    valid: bool,
}

async fn kms_verify(
    State(_state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<KmsVerifyRequest>,
) -> Result<Json<KmsVerifyResponse>, ApiError> {
    require_scope(&user, "kms:verify")?;
    extract_tenant_id(&headers, &user)?;
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
    Ok(Json(KmsVerifyResponse { valid }))
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<u32>,
}

#[derive(Serialize)]
struct AuditLogEntryResponse {
    id: String,
    tenant_id: String,
    event_type: String,
    event_hash_b64: String,
    prev_hash_b64: Option<String>,
    metadata: serde_json::Value,
    created_at: u64,
}

async fn kms_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditLogEntryResponse>>, ApiError> {
    require_scope(&user, "kms:audit:read")?;
    let tenant_id = extract_tenant_id(&headers, &user)?;
    let limit = query.limit.unwrap_or(25).min(100) as i64;
    let mut logs = state
        .kms
        .list_audit_logs(tenant_id, limit)
        .await
        .map_err(ApiError::from)?;
    logs.reverse();
    Ok(Json(
        logs
            .into_iter()
            .map(|entry| AuditLogEntryResponse {
                id: entry.id.to_string(),
                tenant_id: entry.tenant_id.to_string(),
                event_type: entry.event_type,
                event_hash_b64: STANDARD.encode(entry.event_hash),
                prev_hash_b64: entry.prev_hash.map(|hash| STANDARD.encode(hash)),
                metadata: entry.metadata,
                created_at: entry.created_at.and_utc().timestamp() as u64,
            })
            .collect(),
    ))
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
    let algorithm = pq::PqAlgorithm::from_name(payload.algorithm.as_deref())
        .map_err(|_| ApiError::InvalidInput("Unsupported PQ algorithm"))?;
    let keypair = pq::keypair(algorithm);
    state
        .kms
        .store_pq_keypair(
            tenant_id,
            &keypair.algorithm.to_string(),
            &keypair.public_key,
            &keypair.secret_key,
        )
        .await
        .map_err(ApiError::from)?;
    Ok(Json(PqKeypairResponse {
        algorithm: keypair.algorithm.to_string(),
        version: 1,
        public_key_b64: STANDARD.encode(keypair.public_key),
    }))
}

#[derive(Serialize)]
struct PqX25519Response {
    public_key_b64: String,
}

async fn kms_pq_x25519(
    State(_state): State<AppState>,
    headers: HeaderMap,
    user: AuthUser,
) -> Result<Json<PqX25519Response>, ApiError> {
    require_scope(&user, "kms:pq:session")?;
    extract_tenant_id(&headers, &user)?;
    let (public_key, _secret_key) = pq::generate_x25519_keypair();
    Ok(Json(PqX25519Response {
        public_key_b64: STANDARD.encode(public_key),
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
                KmsError::InvalidInput | KmsError::InvalidAlgorithm => {
                    (StatusCode::BAD_REQUEST, "Invalid request")
                }
                KmsError::RotationNotEnabled | KmsError::RotationConfirmationMissing => {
                    (StatusCode::FORBIDDEN, "Rotation not allowed")
                }
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
