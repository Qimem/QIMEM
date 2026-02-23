use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use qimem::api::{router, AppState};
use qimem::{InMemoryKeyStore, KeyStore};
use serde_json::Value;
use tower::util::ServiceExt;

#[tokio::test]
async fn encrypt_and_decrypt_use_input_field_contract() {
    let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::default());
    let key = store.create_key().expect("create key");
    let app = router(AppState { store });

    let encrypt_body = serde_json::json!({
        "key_id": key.key_id,
        "input": "hello"
    })
    .to_string();

    let encrypt_response = app
        .clone()
        .oneshot(
            Request::post("/encrypt")
                .header("content-type", "application/json")
                .body(Body::from(encrypt_body))
                .expect("build encrypt request"),
        )
        .await
        .expect("encrypt response");
    assert_eq!(encrypt_response.status(), StatusCode::OK);

    let encrypt_bytes = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .expect("read encrypt body");
    let encrypt_json: Value = serde_json::from_slice(&encrypt_bytes).expect("valid encrypt json");
    let envelope = encrypt_json
        .get("envelope")
        .and_then(Value::as_str)
        .expect("envelope string");

    let decrypt_body = serde_json::json!({ "input": envelope }).to_string();
    let decrypt_response = app
        .oneshot(
            Request::post("/decrypt")
                .header("content-type", "application/json")
                .body(Body::from(decrypt_body))
                .expect("build decrypt request"),
        )
        .await
        .expect("decrypt response");
    assert_eq!(decrypt_response.status(), StatusCode::OK);

    let decrypt_bytes = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .expect("read decrypt body");
    let decrypt_json: Value = serde_json::from_slice(&decrypt_bytes).expect("valid decrypt json");
    assert_eq!(
        decrypt_json.get("plaintext"),
        Some(&Value::String("hello".to_string()))
    );
}

#[tokio::test]
async fn encrypt_rejects_plaintext_field_name() {
    let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::default());
    let key = store.create_key().expect("create key");
    let app = router(AppState { store });

    let encrypt_body = serde_json::json!({
        "key_id": key.key_id,
        "plaintext": "hello"
    })
    .to_string();

    let response = app
        .oneshot(
            Request::post("/encrypt")
                .header("content-type", "application/json")
                .body(Body::from(encrypt_body))
                .expect("build request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
