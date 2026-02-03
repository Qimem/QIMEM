use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::q_core;
use crate::q_keygen;
use crate::signing;
use crate::totp;
use crate::pq;

use super::auth::{AuthConfig, AuthError, AuthUser};
use super::policy::{PolicyConfig, PolicyError};

#[derive(Clone, Debug)]
pub struct AppState {
    pub auth: AuthConfig,
    pub policy: PolicyConfig,
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

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", axum::routing::get(health))
        .route("/v1/derive-key", axum::routing::post(derive_key))
        .route("/v1/encrypt", axum::routing::post(encrypt))
        .route("/v1/decrypt", axum::routing::post(decrypt))
        .route("/v1/sign", axum::routing::post(sign))
        .route("/v1/verify", axum::routing::post(verify))
        .route("/v1/totp/secret", axum::routing::post(totp_secret))
        .route("/v1/totp/code", axum::routing::post(totp_code))
        .route("/v1/totp/verify", axum::routing::post(totp_verify))
        .route("/v1/pq/keypair", axum::routing::post(pq_keypair))
        .route("/v1/pq/encapsulate", axum::routing::post(pq_encapsulate))
        .route("/v1/pq/decapsulate", axum::routing::post(pq_decapsulate))
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

#[derive(Serialize)]
struct TotpSecretResponse {
    secret_b64: String,
}

async fn totp_secret(
    State(_state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<TotpSecretResponse>, ApiError> {
    let secret = totp::generate_totp_secret_bytes().map_err(|_| ApiError::Crypto("TOTP failed"))?;
    Ok(Json(TotpSecretResponse {
        secret_b64: STANDARD.encode(secret),
    }))
}

#[derive(Deserialize)]
struct TotpCodeRequest {
    secret_b64: String,
}

#[derive(Serialize)]
struct TotpCodeResponse {
    code: String,
}

async fn totp_code(
    State(_state): State<AppState>,
    _user: AuthUser,
    Json(payload): Json<TotpCodeRequest>,
) -> Result<Json<TotpCodeResponse>, ApiError> {
    let secret = STANDARD
        .decode(payload.secret_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid secret base64"))?;
    let code = totp::get_totp_code_bytes(&secret).map_err(|_| ApiError::Crypto("TOTP failed"))?;
    Ok(Json(TotpCodeResponse { code }))
}

#[derive(Deserialize)]
struct TotpVerifyRequest {
    secret_b64: String,
    code: String,
}

#[derive(Serialize)]
struct TotpVerifyResponse {
    valid: bool,
}

async fn totp_verify(
    State(_state): State<AppState>,
    _user: AuthUser,
    Json(payload): Json<TotpVerifyRequest>,
) -> Result<Json<TotpVerifyResponse>, ApiError> {
    let secret = STANDARD
        .decode(payload.secret_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid secret base64"))?;
    let valid = totp::verify_totp_code_bytes(&secret, &payload.code)
        .map_err(|_| ApiError::Crypto("TOTP failed"))?;
    Ok(Json(TotpVerifyResponse { valid }))
}

#[derive(Serialize)]
struct PqKeypairResponse {
    public_key_b64: String,
    secret_key_b64: String,
}

async fn pq_keypair(
    State(_state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<PqKeypairResponse>, ApiError> {
    let (public_key, secret_key) = pq::kyber_keypair();
    Ok(Json(PqKeypairResponse {
        public_key_b64: STANDARD.encode(public_key),
        secret_key_b64: STANDARD.encode(secret_key),
    }))
}

#[derive(Deserialize)]
struct PqEncapsulateRequest {
    public_key_b64: String,
}

#[derive(Serialize)]
struct PqEncapsulateResponse {
    ciphertext_b64: String,
    shared_secret_b64: String,
}

async fn pq_encapsulate(
    State(_state): State<AppState>,
    _user: AuthUser,
    Json(payload): Json<PqEncapsulateRequest>,
) -> Result<Json<PqEncapsulateResponse>, ApiError> {
    let public_key = STANDARD
        .decode(payload.public_key_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid public key base64"))?;
    let (ciphertext, shared_secret) = pq::kyber_encapsulate(&public_key)
        .map_err(|_| ApiError::Crypto("Encapsulation failed"))?;
    Ok(Json(PqEncapsulateResponse {
        ciphertext_b64: STANDARD.encode(ciphertext),
        shared_secret_b64: STANDARD.encode(shared_secret),
    }))
}

#[derive(Deserialize)]
struct PqDecapsulateRequest {
    secret_key_b64: String,
    ciphertext_b64: String,
}

#[derive(Serialize)]
struct PqDecapsulateResponse {
    shared_secret_b64: String,
}

async fn pq_decapsulate(
    State(_state): State<AppState>,
    _user: AuthUser,
    Json(payload): Json<PqDecapsulateRequest>,
) -> Result<Json<PqDecapsulateResponse>, ApiError> {
    let secret_key = STANDARD
        .decode(payload.secret_key_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid secret key base64"))?;
    let ciphertext = STANDARD
        .decode(payload.ciphertext_b64)
        .map_err(|_| ApiError::InvalidInput("Invalid ciphertext base64"))?;
    let shared_secret = pq::kyber_decapsulate(&secret_key, &ciphertext)
        .map_err(|_| ApiError::Crypto("Decapsulation failed"))?;
    Ok(Json(PqDecapsulateResponse {
        shared_secret_b64: STANDARD.encode(shared_secret),
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
