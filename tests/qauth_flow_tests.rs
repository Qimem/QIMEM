use std::sync::{Arc, RwLock};

use axum::http::{Request, StatusCode};
use qimem::platform_api::{router, PlatformState};
use qimem::qauth::QAuthService;
use qimem::{InMemoryKeyStore, KeyStore};
use tower::ServiceExt;

#[tokio::test]
async fn qauth_login_refresh_revoke_flow_works() {
    let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::default());
    let qauth = QAuthService::new();
    qauth.create_realm("acme", "Acme").unwrap();
    qauth
        .create_role(
            "acme",
            "admin",
            vec!["keys:encrypt".into(), "keys:decrypt".into()],
        )
        .unwrap();
    let client = qauth
        .create_client("acme", vec!["http://localhost/cb".into()])
        .unwrap();
    qauth
        .create_user("acme", "alice", "secret-password", vec!["admin".into()])
        .unwrap();

    let app = router(PlatformState {
        qauth,
        store,
        plugins: Arc::new(RwLock::new(Vec::new())),
    });

    let login_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/token")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({
                "client_id": client.client_id,
                "client_secret": client.client_secret,
                "realm_id": "acme",
                "username": "alice",
                "password": "secret-password"
            })
            .to_string(),
        ))
        .unwrap();
    let login_resp = app.clone().oneshot(login_req).await.unwrap();
    assert_eq!(login_resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(login_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let login_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access = login_json["access_token"].as_str().unwrap();
    let refresh = login_json["refresh_token"].as_str().unwrap();

    let introspect_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/token/introspect")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({"token": access}).to_string(),
        ))
        .unwrap();
    let introspect_resp = app.clone().oneshot(introspect_req).await.unwrap();
    assert_eq!(introspect_resp.status(), StatusCode::OK);

    let refresh_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/token/refresh")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({"refresh_token": refresh}).to_string(),
        ))
        .unwrap();
    let refresh_resp = app.clone().oneshot(refresh_req).await.unwrap();
    assert_eq!(refresh_resp.status(), StatusCode::OK);

    let revoke_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/token/revoke")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({"token": access}).to_string(),
        ))
        .unwrap();
    let revoke_resp = app.clone().oneshot(revoke_req).await.unwrap();
    assert_eq!(revoke_resp.status(), StatusCode::OK);

    let introspect_again_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/token/introspect")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({"token": access}).to_string(),
        ))
        .unwrap();
    let introspect_again_resp = app.oneshot(introspect_again_req).await.unwrap();
    assert_eq!(introspect_again_resp.status(), StatusCode::BAD_REQUEST);
}
