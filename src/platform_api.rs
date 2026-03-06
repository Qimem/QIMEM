//! Unified platform API for QAuth, QIMEM security, and plugins.

use std::sync::{Arc, RwLock};

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::QimemError;
use crate::keystore::KeyStore;
use crate::qauth::QAuthService;
use crate::{Algorithm, CryptoEngine, Envelope};

/// Plugin manifest definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Unique plugin name.
    pub name: String,
    /// Semantic version.
    pub version: String,
    /// Runtime type (e.g. wasm, python, js, lua).
    pub runtime: String,
    /// Capabilities exposed by plugin.
    pub capabilities: Vec<String>,
}

/// Platform app state.
#[derive(Clone)]
pub struct PlatformState {
    /// QAuth service.
    pub qauth: QAuthService,
    /// Shared key store for QIMEM security endpoints.
    pub store: Arc<dyn KeyStore>,
    /// Plugin manifests.
    pub plugins: Arc<RwLock<Vec<PluginManifest>>>,
}

/// Build root router with versioning.
pub fn router(state: PlatformState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/security/health", get(health))
        .route("/v1/security/keys", post(create_key))
        .route("/v1/security/encrypt", post(encrypt))
        .route("/v1/security/decrypt", post(decrypt))
        .route("/v1/security/rotate", post(rotate_key))
        .route("/v1/auth/realms", post(create_realm))
        .route("/v1/auth/roles", post(create_role))
        .route("/v1/auth/clients", post(create_client))
        .route("/v1/auth/users", post(create_user))
        .route("/v1/auth/token", post(login))
        .route("/v1/auth/token/refresh", post(refresh))
        .route("/v1/auth/token/revoke", post(revoke))
        .route("/v1/auth/token/introspect", post(introspect))
        .route("/v1/auth/keys/rotate", post(rotate_signing_key))
        .route(
            "/v1/plugins/manifests",
            get(list_plugins).post(register_plugin),
        )
        .with_state(state)
}

#[derive(Serialize)]
struct StatusResponse<'a> {
    status: &'a str,
}

async fn health() -> Json<StatusResponse<'static>> {
    Json(StatusResponse { status: "ok" })
}

async fn ready() -> Json<StatusResponse<'static>> {
    Json(StatusResponse { status: "ready" })
}

type ApiResult<T> = std::result::Result<Json<T>, (axum::http::StatusCode, Json<ErrorResponse>)>;

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn map_err(err: QimemError) -> (axum::http::StatusCode, Json<ErrorResponse>) {
    let status = match err {
        QimemError::KeyNotFound(_) => axum::http::StatusCode::NOT_FOUND,
        _ => axum::http::StatusCode::BAD_REQUEST,
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
}

async fn create_key(State(state): State<PlatformState>) -> ApiResult<CreateKeyResponse> {
    let key = state.store.create_key().map_err(map_err)?;
    Ok(Json(CreateKeyResponse { key_id: key.key_id }))
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
    State(state): State<PlatformState>,
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
    State(state): State<PlatformState>,
    Json(req): Json<DecryptRequest>,
) -> ApiResult<DecryptResponse> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(req.input)
        .map_err(|_| map_err(QimemError::InvalidEnvelope("invalid base64")))?;
    let envelope = Envelope::deserialize_binary(&bytes).map_err(map_err)?;
    let key = state.store.get_key(envelope.key_id).map_err(map_err)?;
    let plaintext = CryptoEngine::new(envelope.algorithm)
        .decrypt(&key, &envelope)
        .map_err(map_err)?;
    let plaintext = String::from_utf8(plaintext).map_err(|_| map_err(QimemError::Decryption))?;
    Ok(Json(DecryptResponse { plaintext }))
}

#[derive(Deserialize)]
struct RotateRequest {
    key_id: Uuid,
}

async fn rotate_key(
    State(state): State<PlatformState>,
    Json(req): Json<RotateRequest>,
) -> ApiResult<serde_json::Value> {
    let key = state.store.rotate_key(req.key_id).map_err(map_err)?;
    Ok(Json(serde_json::json!(key)))
}

#[derive(Deserialize)]
struct CreateRealmRequest {
    id: String,
    name: String,
}

async fn create_realm(
    State(state): State<PlatformState>,
    Json(req): Json<CreateRealmRequest>,
) -> ApiResult<serde_json::Value> {
    let realm = state
        .qauth
        .create_realm(&req.id, &req.name)
        .map_err(map_err)?;
    Ok(Json(serde_json::to_value(realm).map_err(|e| {
        map_err(QimemError::Serialization(e.to_string()))
    })?))
}

#[derive(Deserialize)]
struct CreateRoleRequest {
    realm_id: String,
    name: String,
    permissions: Vec<String>,
}

async fn create_role(
    State(state): State<PlatformState>,
    Json(req): Json<CreateRoleRequest>,
) -> ApiResult<serde_json::Value> {
    let role = state
        .qauth
        .create_role(&req.realm_id, &req.name, req.permissions)
        .map_err(map_err)?;
    Ok(Json(serde_json::to_value(role).map_err(|e| {
        map_err(QimemError::Serialization(e.to_string()))
    })?))
}

#[derive(Deserialize)]
struct CreateClientRequest {
    realm_id: String,
    redirect_uris: Vec<String>,
}

async fn create_client(
    State(state): State<PlatformState>,
    Json(req): Json<CreateClientRequest>,
) -> ApiResult<serde_json::Value> {
    let client = state
        .qauth
        .create_client(&req.realm_id, req.redirect_uris)
        .map_err(map_err)?;
    Ok(Json(serde_json::to_value(client).map_err(|e| {
        map_err(QimemError::Serialization(e.to_string()))
    })?))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    realm_id: String,
    username: String,
    password: String,
    roles: Vec<String>,
    totp_secret: Option<String>,
}

async fn create_user(
    State(state): State<PlatformState>,
    Json(req): Json<CreateUserRequest>,
) -> ApiResult<serde_json::Value> {
    let user = state
        .qauth
        .create_user(&req.realm_id, &req.username, &req.password, req.roles)
        .map_err(map_err)?;
    if let Some(secret) = req.totp_secret {
        state
            .qauth
            .set_totp_secret(&req.realm_id, &req.username, secret)
            .map_err(map_err)?;
    }
    Ok(Json(
        serde_json::json!({"id": user.id, "username": user.username, "realm_id": user.realm_id}),
    ))
}

#[derive(Deserialize)]
struct LoginRequest {
    client_id: String,
    client_secret: String,
    realm_id: String,
    username: String,
    password: String,
    totp_code: Option<String>,
}

async fn login(
    State(state): State<PlatformState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<serde_json::Value> {
    let pair = state
        .qauth
        .login(
            &req.client_id,
            &req.client_secret,
            &req.realm_id,
            &req.username,
            &req.password,
            req.totp_code.as_deref(),
        )
        .map_err(map_err)?;
    Ok(Json(serde_json::to_value(pair).map_err(|e| {
        map_err(QimemError::Serialization(e.to_string()))
    })?))
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

async fn refresh(
    State(state): State<PlatformState>,
    Json(req): Json<RefreshRequest>,
) -> ApiResult<serde_json::Value> {
    let pair = state.qauth.refresh(&req.refresh_token).map_err(map_err)?;
    Ok(Json(serde_json::to_value(pair).map_err(|e| {
        map_err(QimemError::Serialization(e.to_string()))
    })?))
}

#[derive(Deserialize)]
struct TokenRequest {
    token: String,
}

async fn revoke(
    State(state): State<PlatformState>,
    Json(req): Json<TokenRequest>,
) -> ApiResult<serde_json::Value> {
    state.qauth.revoke(&req.token).map_err(map_err)?;
    Ok(Json(serde_json::json!({"revoked": true})))
}

async fn introspect(
    State(state): State<PlatformState>,
    Json(req): Json<TokenRequest>,
) -> ApiResult<serde_json::Value> {
    let out = state.qauth.introspect_access(&req.token).map_err(map_err)?;
    Ok(Json(out))
}

async fn rotate_signing_key(State(state): State<PlatformState>) -> ApiResult<serde_json::Value> {
    let kid = state.qauth.rotate_signing_key().map_err(map_err)?;
    Ok(Json(serde_json::json!({"kid": kid})))
}

async fn list_plugins(State(state): State<PlatformState>) -> ApiResult<Vec<PluginManifest>> {
    let plugins = state
        .plugins
        .read()
        .map_err(|_| map_err(QimemError::Config("plugin lock poisoned".into())))?
        .clone();
    Ok(Json(plugins))
}

async fn register_plugin(
    State(state): State<PlatformState>,
    Json(req): Json<PluginManifest>,
) -> ApiResult<PluginManifest> {
    state
        .plugins
        .write()
        .map_err(|_| map_err(QimemError::Config("plugin lock poisoned".into())))?
        .push(req.clone());
    Ok(Json(req))
}
