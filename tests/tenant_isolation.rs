use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::RngCore;
use serde::Serialize;
use tower::ServiceExt;

use qimem::server::{router, AppState, AuthConfig, DbState, PolicyConfig, RootKey};

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
    tenant_id: String,
    scopes: Vec<String>,
}

#[tokio::test]
async fn test_tenant_header_mismatch_rejected() {
    let database_url = match std::env::var("QIMEM_DATABASE_URL") {
        Ok(value) => value,
        Err(_) => return,
    };
    let db = DbState::connect(&database_url).await.unwrap();
    let auth = AuthConfig {
        jwt_secret: "test-secret".to_string(),
        issuer: None,
        audience: None,
        auth_disabled: false,
    };
    let policy = PolicyConfig::from_env();
    let root_key = RootKey::from_env().unwrap_or_else(|_| {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let encoded = STANDARD.encode(bytes);
        std::env::set_var("QIMEM_ROOT_KEY_B64", encoded);
        RootKey::from_env().expect("root key")
    });

    let state = AppState {
        auth,
        policy,
        db,
        root_key,
    };
    let app: Router = router(state);

    let tenant_a = uuid::Uuid::new_v4();
    let tenant_b = uuid::Uuid::new_v4();
    let claims = Claims {
        sub: "user".to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        tenant_id: tenant_a.to_string(),
        scopes: vec!["kms:decrypt".to_string()],
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("test-secret".as_bytes()),
    )
    .unwrap();

    let request = Request::builder()
        .uri("/v1/kms/decrypt")
        .method("POST")
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Tenant-ID", tenant_b.to_string())
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{\"ciphertext_b64\":\"\",\"wrapped_dek_b64\":\"\",\"key_version\":1,\"nonce_b64\":\"\",\"algorithm\":\"chacha20poly1305\"}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
