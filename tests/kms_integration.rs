use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use qimem::pq;
use qimem::server::kms::{
    append_audit_log, generate_master_key, rotate_root_key, unwrap_key, wrap_key, KmsError,
    RootRotationOptions,
};

mod test_support;

#[tokio::test]
async fn test_encrypt_rotate_decrypt() {
    if !test_support::docker_available() {
        eprintln!("Skipping test_encrypt_rotate_decrypt: Docker not available.");
        return;
    }
    let test_db = test_support::setup_test_db().await;
    let tenant_id = uuid::Uuid::new_v4();
    let mut root_key = [7u8; 32];
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
    test_db.db.insert_tenant(&tenant).await.unwrap();
    test_db
        .db
        .insert_master_key_version(tenant_id, 1, &wrapped_master_key, now)
        .await
        .unwrap();

    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);
    let cipher = ChaCha20Poly1305::new_from_slice(&dek).unwrap();
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), b"secret payload".as_slice())
        .unwrap();
    let wrapped_dek = wrap_key(&dek, &unwrap_key(&wrapped_master_key, &root_key).unwrap()).unwrap();

    let mut new_master = generate_master_key();
    let wrapped_master_v2 = wrap_key(&new_master, &root_key).unwrap();
    new_master.zeroize();
    let now_v2 = chrono::Utc::now().naive_utc();
    test_db
        .db
        .insert_master_key_version(tenant_id, 2, &wrapped_master_v2, now_v2)
        .await
        .unwrap();
    test_db
        .db
        .update_tenant_key_version(tenant_id, 2, now_v2)
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
    if !test_support::docker_available() {
        eprintln!("Skipping test_cross_tenant_isolation: Docker not available.");
        return;
    }
    let test_db = test_support::setup_test_db().await;
    let tenant_a = uuid::Uuid::new_v4();
    let tenant_b = uuid::Uuid::new_v4();
    let mut root_key = [9u8; 32];
    let mut master_a = generate_master_key();
    let wrapped_a = wrap_key(&master_a, &root_key).unwrap();
    master_a.zeroize();
    let mut master_b = generate_master_key();
    let wrapped_b = wrap_key(&master_b, &root_key).unwrap();
    master_b.zeroize();
    let now = chrono::Utc::now().naive_utc();
    test_db
        .db
        .insert_tenant(&qimem::server::kms::TenantRecord {
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
    test_db
        .db
        .insert_tenant(&qimem::server::kms::TenantRecord {
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
    test_db
        .db
        .insert_master_key_version(tenant_a, 1, &wrapped_a, now)
        .await
        .unwrap();
    test_db
        .db
        .insert_master_key_version(tenant_b, 1, &wrapped_b, now)
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
    let (server_public, session_key, _ciphertext) = pq::hybrid_session(
        pq::PqAlgorithm::Kyber1024,
        client_public.as_bytes(),
        &kyber.public_key,
    )
    .unwrap();
    assert_eq!(server_public.len(), 32);
    assert_eq!(session_key.len(), 32);
    assert!(pq::PqAlgorithm::Kyber1024
        .algorithm_id()
        .as_bytes()
        .ct_eq(b"kyber1024")
        .unwrap_u8()
        == 1);
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

#[tokio::test]
async fn test_root_rotation_requires_flags() {
    let err = rotate_root_key(RootRotationOptions {
        dry_run: true,
        enable_destructive: false,
        confirmation: "".to_string(),
    })
    .await
    .unwrap_err();
    assert!(matches!(err, KmsError::RotationNotEnabled));
}

#[tokio::test]
async fn test_root_rotation_requires_confirmation() {
    let err = rotate_root_key(RootRotationOptions {
        dry_run: true,
        enable_destructive: true,
        confirmation: "nope".to_string(),
    })
    .await
    .unwrap_err();
    assert!(matches!(err, KmsError::RotationConfirmationMissing));
}

#[tokio::test]
async fn test_root_rotation_rewraps_keys() {
    if !test_support::docker_available() {
        eprintln!("Skipping test_root_rotation_rewraps_keys: Docker not available.");
        return;
    }
    let test_db = test_support::setup_test_db().await;
    let tenant_id = uuid::Uuid::new_v4();
    let old_root = [1u8; 32];
    let new_root = [2u8; 32];
    let old_root_b64 = STANDARD.encode(old_root);
    let new_root_b64 = STANDARD.encode(new_root);

    std::env::set_var("QIMEM_DATABASE_URL", test_db.database_url);
    std::env::set_var("QIMEM_ROOT_KEY_SOURCE", "env");
    std::env::set_var("QIMEM_ROOT_KEY_B64", old_root_b64);
    std::env::set_var("QIMEM_NEW_ROOT_KEY_B64", new_root_b64);

    let mut master_key = generate_master_key();
    let wrapped_master_key = wrap_key(&master_key, &old_root).unwrap();
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
    test_db.db.insert_tenant(&tenant).await.unwrap();
    test_db
        .db
        .insert_master_key_version(tenant_id, 1, &wrapped_master_key, now)
        .await
        .unwrap();

    rotate_root_key(RootRotationOptions {
        dry_run: false,
        enable_destructive: true,
        confirmation: "CONFIRM_ROOT_ROTATION_AND_DATA_REENCRYPTION".to_string(),
    })
    .await
    .unwrap();

    let updated = test_db
        .db
        .fetch_master_key_version(tenant_id, 1)
        .await
        .unwrap();
    let attempt_old = unwrap_key(&updated.wrapped_master_key, &old_root);
    assert!(attempt_old.is_err());
}
