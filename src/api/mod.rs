//! HTTP API.

use std::sync::Arc;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{QimemError, Result};
use crate::keystore::KeyStore;
use crate::{Algorithm, CryptoEngine, Envelope};

/// Shared app state.
#[derive(Clone)]
pub struct AppState {
    /// Key store backend.
    pub store: Arc<dyn KeyStore>,
}

/// Build API router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/keys", post(create_key))
        .route("/encrypt", post(encrypt))
        .route("/decrypt", post(decrypt))
        .route("/rotate", post(rotate))
        .with_state(state)
}

#[derive(Serialize)]
struct HealthResponse<'a> {
    status: &'a str,
}

async fn health() -> Json<HealthResponse<'static>> {
    Json(HealthResponse { status: "ok" })
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

type ApiResult<T> = std::result::Result<Json<T>, (axum::http::StatusCode, Json<ErrorResponse>)>;

fn map_err(err: QimemError) -> (axum::http::StatusCode, Json<ErrorResponse>) {
    let status = match err {
        QimemError::KeyNotFound(_) => axum::http::StatusCode::NOT_FOUND,
        QimemError::UnsupportedVersion(_)
        | QimemError::UnsupportedAlgorithm(_)
        | QimemError::InvalidEnvelope(_)
        | QimemError::Serialization(_)
        | QimemError::KeyInactive(_) => axum::http::StatusCode::BAD_REQUEST,
        _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(ErrorResponse {
            error: err.to_string(),
        }),
    )
}

#[derive(Serialize)]
struct CreateKeyResponse {
    key_id: Uuid,
    lineage_id: Uuid,
    version: i32,
    active: bool,
}

async fn create_key(State(state): State<AppState>) -> ApiResult<CreateKeyResponse> {
    let key = state.store.create_key().map_err(map_err)?;
    Ok(Json(CreateKeyResponse {
        key_id: key.key_id,
        lineage_id: key.lineage_id,
        version: key.version,
        active: key.active,
    }))
}

#[derive(Deserialize)]
struct EncryptRequest {
    key_id: Uuid,
    input: String,
}
#[derive(Serialize)]
struct EncryptResponse {
    envelope: String,
}

async fn encrypt(
    State(state): State<AppState>,
    Json(req): Json<EncryptRequest>,
) -> ApiResult<EncryptResponse> {
    let key = state.store.get_key(req.key_id).map_err(map_err)?;
    let engine = CryptoEngine::new(Algorithm::Aes256Gcm);
    let envelope = engine
        .encrypt(&key, req.input.as_bytes())
        .map_err(map_err)?;
    let binary = envelope.serialize_binary().map_err(map_err)?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(binary);
    Ok(Json(EncryptResponse { envelope: encoded }))
}

#[derive(Deserialize)]
struct DecryptRequest {
    input: String,
}
#[derive(Serialize)]
struct DecryptResponse {
    plaintext: String,
}

async fn decrypt(
    State(state): State<AppState>,
    Json(req): Json<DecryptRequest>,
) -> ApiResult<DecryptResponse> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(req.input)
        .map_err(|_| map_err(QimemError::InvalidEnvelope("invalid base64")))?;
    let envelope = Envelope::deserialize_binary(&bytes).map_err(map_err)?;
    let key = state.store.get_key(envelope.key_id).map_err(map_err)?;
    let engine = CryptoEngine::new(envelope.algorithm);
    let plaintext = engine.decrypt(&key, &envelope).map_err(map_err)?;
    let plaintext = String::from_utf8(plaintext).map_err(|_| map_err(QimemError::Decryption))?;
    Ok(Json(DecryptResponse { plaintext }))
}

#[derive(Deserialize)]
struct RotateRequest {
    key_id: Uuid,
}
#[derive(Serialize)]
struct RotateResponse {
    key_id: Uuid,
    lineage_id: Uuid,
    version: i32,
    active: bool,
}

async fn rotate(
    State(state): State<AppState>,
    Json(req): Json<RotateRequest>,
) -> ApiResult<RotateResponse> {
    let key = state.store.rotate_key(req.key_id).map_err(map_err)?;
    Ok(Json(RotateResponse {
        key_id: key.key_id,
        lineage_id: key.lineage_id,
        version: key.version,
        active: key.active,
    }))
}

#[allow(dead_code)]
fn _ensure_result_alias(_: Result<()>) {}
