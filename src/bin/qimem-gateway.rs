use std::env;
use std::net::SocketAddr;

use axum::extract::{FromRef, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::post, Json, Router};
use reqwest::header::HeaderMap as ReqwestHeaderMap;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

use qimem::server::auth::{AuthConfig, AuthError, AuthUser};
use qimem::server::KmsService;

#[derive(Clone, Debug)]
struct GatewayState {
    auth: AuthConfig,
    kms: KmsService,
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

#[derive(Debug, thiserror::Error)]
enum GatewayStartupError {
    #[error("Missing QIMEM authentication configuration: {0}")]
    Auth(#[from] AuthError),
    #[error("Missing or invalid KMS configuration")]
    Kms,
    #[error("Invalid host/port")]
    Addr,
    #[error("Failed to bind listener: {0}")]
    Bind(std::io::Error),
    #[error("Server error: {0}")]
    Serve(std::io::Error),
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), GatewayStartupError> {
    dotenvy::dotenv().ok();
    let host = env::var("QIMEM_GATEWAY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = env::var("QIMEM_GATEWAY_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8081);

    let auth = AuthConfig::from_env()?;
    let kms = KmsService::from_env()
        .await
        .map_err(|_| GatewayStartupError::Kms)?;

    let state = GatewayState { auth, kms };

    let app = Router::new()
        .route("/v1/gateway/proxy", post(proxy_handler))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .map_err(|_| GatewayStartupError::Addr)?;
    println!("QIMEM Gateway listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(GatewayStartupError::Bind)?;
    axum::serve(listener, app)
        .await
        .map_err(GatewayStartupError::Serve)
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
    let mut plaintext = state
        .kms
        .decrypt_for_gateway(
            tenant_id,
            payload.wrapped_dek.clone(),
            payload.encrypted_payload.clone(),
            payload.nonce.clone(),
            payload.algorithm.clone(),
            payload.key_version,
        )
        .await
        .map_err(|_| GatewayError::Crypto("Decryption failed"))?;

    let provider_response = match payload.provider.as_str() {
        "mock" => {
            plaintext.reverse();
            String::from_utf8_lossy(&plaintext).to_string()
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
                .body(plaintext.to_vec())
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

    state
        .kms
        .log_gateway_decrypt(
            tenant_id,
            serde_json::json!({
                "provider": payload.provider,
                "key_version": payload.key_version,
            }),
        )
        .await
        .map_err(|_| GatewayError::Crypto("Audit write failed"))?;

    plaintext.zeroize();

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
    let user_tenant_id = Uuid::parse_str(user_tenant)
        .map_err(|_| GatewayError::InvalidInput("Invalid tenant id"))?;
    if tenant_id
        .as_bytes()
        .ct_eq(user_tenant_id.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(GatewayError::Auth(AuthError::InvalidToken));
    }
    Ok(tenant_id)
}

#[derive(Debug)]
enum GatewayError {
    InvalidInput(&'static str),
    Crypto(&'static str),
    Auth(AuthError),
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            GatewayError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            GatewayError::Crypto(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            GatewayError::Auth(err) => {
                let _ = err.to_string();
                (StatusCode::UNAUTHORIZED, "Unauthorized")
            }
        };
        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}
