use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use qimem::pq;
use qimem::server::db::DbState;
use qimem::server::kms::{append_audit_log, generate_master_key, unwrap_key, wrap_key};

async fn setup_pool() -> Option<PgPool> {
    let database_url = std::env::var("QIMEM_DATABASE_URL").ok()?;
    let pool = PgPool::connect(&database_url).await.ok()?;
    Some(pool)
}

async fn setup_schema(pool: &PgPool) {
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenants (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            wrapped_master_key BYTEA NOT NULL,
            key_version INT NOT NULL DEFAULT 1,
            crypto_policy_version INT NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        )",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenant_master_key_versions (
            tenant_id UUID REFERENCES tenants(id),
            version INT NOT NULL,
            wrapped_master_key BYTEA NOT NULL,
            created_at TIMESTAMP NOT NULL,
            PRIMARY KEY (tenant_id, version)
        )",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenant_pq_keys (
            tenant_id UUID REFERENCES tenants(id),
            algorithm TEXT NOT NULL,
            public_key BYTEA NOT NULL,
            wrapped_private_key BYTEA NOT NULL,
            created_at TIMESTAMP NOT NULL
        )",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY,
            tenant_id UUID REFERENCES tenants(id),
            event_type TEXT NOT NULL,
            event_hash BYTEA NOT NULL,
            prev_hash BYTEA,
            metadata JSONB,
            created_at TIMESTAMP NOT NULL
        )",
    )
    .execute(pool)
    .await;
}

#[tokio::test]
async fn test_encrypt_rotate_decrypt() {
    let Some(pool) = setup_pool().await else {
        return;
    };
    setup_schema(&pool).await;
    let db = DbState::connect(&std::env::var("QIMEM_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let tenant_id = uuid::Uuid::new_v4();
    let mut root_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut root_key);
    let mut master_key = generate_master_key();
    let wrapped_master_key = wrap_key(&master_key, &root_key).unwrap();
    master_key.zeroize();
    let now = chrono::Utc::now().naive_utc();
    let tenant = qimem::server::kms::TenantRecord {
        id: tenant_id,
        name: "tenant-a".to_string(),
        wrapped_master_key: wrapped_master_key.clone(),
        key_version: 1,
        crypto_policy_version: 1,
        created_at: now,
        updated_at: now,
    };
    db.insert_tenant(&tenant).await.unwrap();
    db.insert_master_key_version(tenant_id, 1, &wrapped_master_key, now)
        .await
        .unwrap();

    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);
    let cipher = ChaCha20Poly1305::new_from_slice(&dek).unwrap();
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), b"secret payload")
        .unwrap();
    let wrapped_dek = wrap_key(&dek, &unwrap_key(&wrapped_master_key, &root_key).unwrap()).unwrap();

    let mut new_master = generate_master_key();
    let wrapped_master_v2 = wrap_key(&new_master, &root_key).unwrap();
    new_master.zeroize();
    let now_v2 = chrono::Utc::now().naive_utc();
    db.insert_master_key_version(tenant_id, 2, &wrapped_master_v2, now_v2)
        .await
        .unwrap();
    db.update_tenant_key_version(tenant_id, 2, now_v2)
        .await
        .unwrap();

    let master_v1 = unwrap_key(&wrapped_master_key, &root_key).unwrap();
    let dek_unwrapped = unwrap_key(&wrapped_dek, &master_v1).unwrap();
    let cipher = ChaCha20Poly1305::new_from_slice(&dek_unwrapped).unwrap();
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .unwrap();
    assert_eq!(plaintext, b"secret payload");
}

#[tokio::test]
async fn test_cross_tenant_isolation() {
    let Some(pool) = setup_pool().await else {
        return;
    };
    setup_schema(&pool).await;
    let db = DbState::connect(&std::env::var("QIMEM_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let tenant_a = uuid::Uuid::new_v4();
    let tenant_b = uuid::Uuid::new_v4();
    let mut root_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut root_key);
    let mut master_a = generate_master_key();
    let wrapped_a = wrap_key(&master_a, &root_key).unwrap();
    master_a.zeroize();
    let mut master_b = generate_master_key();
    let wrapped_b = wrap_key(&master_b, &root_key).unwrap();
    master_b.zeroize();
    let now = chrono::Utc::now().naive_utc();
    db.insert_tenant(&qimem::server::kms::TenantRecord {
        id: tenant_a,
        name: "tenant-a".to_string(),
        wrapped_master_key: wrapped_a.clone(),
        key_version: 1,
        crypto_policy_version: 1,
        created_at: now,
        updated_at: now,
    })
    .await
    .unwrap();
    db.insert_tenant(&qimem::server::kms::TenantRecord {
        id: tenant_b,
        name: "tenant-b".to_string(),
        wrapped_master_key: wrapped_b.clone(),
        key_version: 1,
        crypto_policy_version: 1,
        created_at: now,
        updated_at: now,
    })
    .await
    .unwrap();
    db.insert_master_key_version(tenant_a, 1, &wrapped_a, now)
        .await
        .unwrap();
    db.insert_master_key_version(tenant_b, 1, &wrapped_b, now)
        .await
        .unwrap();

    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);
    let wrapped_dek = wrap_key(&dek, &unwrap_key(&wrapped_a, &root_key).unwrap()).unwrap();
    let attempt = unwrap_key(&wrapped_dek, &unwrap_key(&wrapped_b, &root_key).unwrap());
    assert!(attempt.is_err());
}

#[tokio::test]
async fn test_pq_session_metadata() {
    let client_secret = x25519_dalek::StaticSecret::new(rand_core::OsRng);
    let client_public = x25519_dalek::PublicKey::from(&client_secret);
    let kyber = pq::keypair(pq::PqAlgorithm::Kyber1024);
    let (server_public, session_key, _ciphertext) =
        pq::hybrid_session(pq::PqAlgorithm::Kyber1024, client_public.as_bytes(), &kyber.public_key)
            .unwrap();
    assert_eq!(server_public.len(), 32);
    assert_eq!(session_key.len(), 32);
    assert!(pq::PqAlgorithm::Kyber1024.algorithm_id().as_bytes().ct_eq(b"kyber1024").unwrap_u8() == 1);
}

#[tokio::test]
async fn test_audit_chain_integrity() {
    let tenant_id = uuid::Uuid::new_v4();
    let first = append_audit_log(None, tenant_id, "event1", serde_json::json!({"a": 1}));
    let second = append_audit_log(
        Some(first.event_hash.clone()),
        tenant_id,
        "event2",
        serde_json::json!({"b": 2}),
    );
    let recomputed = append_audit_log(
        Some(first.event_hash.clone()),
        tenant_id,
        "event2",
        serde_json::json!({"b": 2}),
    );
    assert_eq!(second.event_hash, recomputed.event_hash);
}
