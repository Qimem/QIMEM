use std::env;
use std::net::SocketAddr;

use axum::extract::{FromRef, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use reqwest::header::HeaderMap as ReqwestHeaderMap;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use qimem::server::auth::{AuthConfig, AuthError, AuthUser};
use qimem::server::db::DbState;
use qimem::server::kms::{append_audit_log, unwrap_key, KmsError, RootKey};

#[derive(Clone, Debug)]
struct GatewayState {
    auth: AuthConfig,
    db: DbState,
    root_key: RootKey,
}

impl FromRef<GatewayState> for AuthConfig {
    fn from_ref(input: &GatewayState) -> Self {
        input.auth.clone()
    }
}

#[derive(Deserialize)]
struct ProxyRequest {
    provider: String,
    encrypted_payload: String,
    wrapped_dek: String,
    key_version: u32,
    provider_config: ProviderConfig,
    nonce: String,
    algorithm: String,
}

#[derive(Deserialize)]
struct ProviderConfig {
    endpoint: Option<String>,
    headers: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize)]
struct ProxyResponse {
    provider: String,
    response: String,
}

#[tokio::main]
async fn main() {
    let host = env::var("QIMEM_GATEWAY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = env::var("QIMEM_GATEWAY_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8081);

    let auth = AuthConfig::from_env().expect("Missing Better Auth configuration");
    let root_key = RootKey::from_env().expect("Missing KMS root key configuration");
    let database_url = env::var("QIMEM_DATABASE_URL").expect("Missing QIMEM_DATABASE_URL");
    let db = DbState::connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    let state = GatewayState { auth, db, root_key };

    let app = Router::new()
        .route("/v1/gateway/proxy", post(proxy_handler))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid host/port");
    println!("QIMEM Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server error");
}

async fn proxy_handler(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, GatewayError> {
    let tenant_id = extract_tenant_id(&headers, &user)?;
    let algorithm_ok = payload
        .algorithm
        .as_bytes()
        .ct_eq(b"chacha20poly1305")
        .unwrap_u8()
        == 1;
    if !algorithm_ok {
        return Err(GatewayError::InvalidInput("Unsupported algorithm"));
    }
    let tenant = state
        .db
        .fetch_tenant(tenant_id)
        .await
        .map_err(|_| GatewayError::Kms(KmsError::TenantNotFound))?;
    let master_version = state
        .db
        .fetch_master_key_version(tenant_id, payload.key_version as i32)
        .await
        .map_err(|_| GatewayError::Kms(KmsError::KeyVersionNotFound))?;
    let mut master_key = unwrap_key(&master_version.wrapped_master_key, state.root_key.expose())
        .map_err(|_| GatewayError::Crypto("Master key unwrap failed"))?;
    let wrapped_dek = STANDARD
        .decode(payload.wrapped_dek)
        .map_err(|_| GatewayError::InvalidInput("Invalid wrapped DEK base64"))?;
    let mut dek = unwrap_key(&wrapped_dek, &master_key)
        .map_err(|_| GatewayError::Crypto("DEK unwrap failed"))?;
    let ciphertext = STANDARD
        .decode(payload.encrypted_payload)
        .map_err(|_| GatewayError::InvalidInput("Invalid ciphertext base64"))?;
    let nonce = STANDARD
        .decode(payload.nonce)
        .map_err(|_| GatewayError::InvalidInput("Invalid nonce base64"))?;
    let plaintext = decrypt_payload(&ciphertext, &nonce, &dek)
        .map_err(|_| GatewayError::Crypto("Decryption failed"))?;
    dek.zeroize();
    master_key.zeroize();

    let provider_response = match payload.provider.as_str() {
        "mock" => {
            let mut reversed = plaintext.clone();
            reversed.reverse();
            String::from_utf8_lossy(&reversed).to_string()
        }
        "custom" => {
            let endpoint = payload
                .provider_config
                .endpoint
                .ok_or(GatewayError::InvalidInput("Missing provider endpoint"))?;
            let mut req_headers = ReqwestHeaderMap::new();
            if let Some(headers) = payload.provider_config.headers {
                for (key, value) in headers {
                    if let Some(value_str) = value.as_str() {
                        req_headers.insert(
                            reqwest::header::HeaderName::from_bytes(key.as_bytes())
                                .map_err(|_| GatewayError::InvalidInput("Invalid header name"))?,
                            reqwest::header::HeaderValue::from_str(value_str)
                                .map_err(|_| GatewayError::InvalidInput("Invalid header value"))?,
                        );
                    }
                }
            }
            let client = reqwest::Client::new();
            let response = client
                .post(endpoint)
                .headers(req_headers)
                .body(plaintext.clone())
                .send()
                .await
                .map_err(|_| GatewayError::Crypto("Provider request failed"))?;
            response
                .text()
                .await
                .map_err(|_| GatewayError::Crypto("Provider response failed"))?
        }
        _ => return Err(GatewayError::InvalidInput("Unsupported provider")),
    };

    let prev_hash = state
        .db
        .fetch_latest_audit_hash(tenant_id)
        .await
        .map_err(|_| GatewayError::Crypto("Audit fetch failed"))?;
    let log_entry = append_audit_log(
        prev_hash,
        tenant_id,
        "decrypt",
        serde_json::json!({
            "provider": payload.provider,
            "key_version": tenant.key_version,
        }),
    );
    state
        .db
        .insert_audit_log(&log_entry)
        .await
        .map_err(|_| GatewayError::Crypto("Audit write failed"))?;

    let mut plaintext_zeroize = plaintext;
    plaintext_zeroize.zeroize();

    Ok(Json(ProxyResponse {
        provider: payload.provider,
        response: provider_response,
    }))
}

fn extract_tenant_id(headers: &HeaderMap, user: &AuthUser) -> Result<Uuid, GatewayError> {
    let header_value = headers
        .get("x-tenant-id")
        .ok_or(GatewayError::Auth(AuthError::MissingAuthorization))?
        .to_str()
        .map_err(|_| GatewayError::InvalidInput("Invalid tenant header"))?;
    let tenant_id = Uuid::parse_str(header_value)
        .map_err(|_| GatewayError::InvalidInput("Invalid tenant id"))?;
    let user_tenant = user
        .tenant_id
        .as_ref()
        .ok_or(GatewayError::Auth(AuthError::InvalidToken))?;
    let user_tenant_id =
        Uuid::parse_str(user_tenant).map_err(|_| GatewayError::InvalidInput("Invalid tenant id"))?;
    if tenant_id.as_bytes().ct_eq(user_tenant_id.as_bytes()).unwrap_u8() != 1 {
        return Err(GatewayError::Auth(AuthError::InvalidToken));
    }
    Ok(tenant_id)
}

fn decrypt_payload(ciphertext: &[u8], nonce_bytes: &[u8], dek: &[u8]) -> Result<Vec<u8>, GatewayError> {
    let cipher = ChaCha20Poly1305::new_from_slice(dek)
        .map_err(|_| GatewayError::Crypto("Decryption failed"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| GatewayError::Crypto("Decryption failed"))
}

#[derive(Debug)]
enum GatewayError {
    InvalidInput(&'static str),
    Crypto(&'static str),
    Auth(AuthError),
    Kms(KmsError),
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            GatewayError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            GatewayError::Crypto(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            GatewayError::Auth(_) => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            GatewayError::Kms(err) => match err {
                KmsError::TenantNotFound => (StatusCode::NOT_FOUND, "Tenant not found"),
                KmsError::KeyVersionNotFound => (StatusCode::NOT_FOUND, "Key version not found"),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "KMS error"),
            },
        };
        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}
