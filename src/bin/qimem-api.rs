use std::net::SocketAddr;

use axum::{
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use qimem::q_core;
use qimem::server::settings::Settings;

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("crypto error")]
    Crypto,
    #[error("utf8 error")]
    Utf8,
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

#[derive(Debug, Deserialize)]
struct EncryptRequest {
    data: String,
    key: String,
}

#[derive(Debug, Serialize)]
struct EncryptResponse {
    encrypted: String,
}

#[derive(Debug, Deserialize)]
struct DecryptRequest {
    data: String,
    key: String,
}

#[derive(Debug, Serialize)]
struct DecryptResponse {
    decrypted: String,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    if let Err(err) = run().await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let settings = Settings::load();

    if settings.auth.jwt_secret.is_none() {
        log::warn!("Auth not configured; running without login features");
    }

    if std::env::var("DATABASE_URL").is_err() {
        log::warn!("DB config missing; skipping migrations");
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/encrypt", post(encrypt_handler))
        .route("/decrypt", post(decrypt_handler));

    let addr: SocketAddr = format!("{}:{}", settings.server.host, settings.server.port).parse()?;
    log::info!("QIMEM API listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

fn derive_key_material(key_seed: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key_seed.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

async fn encrypt_handler(
    Json(payload): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>, ApiError> {
    if payload.data.is_empty() || payload.key.is_empty() {
        return Err(ApiError::InvalidInput("data and key are required"));
    }

    let key = derive_key_material(&payload.key);
    let encrypted =
        q_core::encrypt_simple(payload.data.as_bytes(), &key).map_err(|_| ApiError::Crypto)?;

    Ok(Json(EncryptResponse {
        encrypted: STANDARD.encode(encrypted),
    }))
}

async fn decrypt_handler(
    Json(payload): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>, ApiError> {
    if payload.data.is_empty() || payload.key.is_empty() {
        return Err(ApiError::InvalidInput("data and key are required"));
    }

    let key = derive_key_material(&payload.key);
    let ciphertext = STANDARD
        .decode(payload.data)
        .map_err(|_| ApiError::InvalidInput("data must be base64 ciphertext"))?;
    let decrypted = q_core::decrypt_simple(&ciphertext, &key).map_err(|_| ApiError::Crypto)?;
    let decrypted = String::from_utf8(decrypted).map_err(|_| ApiError::Utf8)?;

    Ok(Json(DecryptResponse { decrypted }))
}
