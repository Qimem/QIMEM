use std::sync::Arc;

use qimem::{Algorithm, CryptoEngine, Envelope, InMemoryKeyStore, KeyStore, QimemError};

#[test]
fn roundtrip_encryption() {
    let store = InMemoryKeyStore::default();
    let key = store.create_key().expect("key");
    let material = store.get_key(key.key_id).expect("material");
    let engine = CryptoEngine::new(Algorithm::Aes256Gcm);
    let envelope = engine.encrypt(&material, b"hello").expect("encrypt");
    let plaintext = engine.decrypt(&material, &envelope).expect("decrypt");
    assert_eq!(plaintext, b"hello");
}

#[test]
fn tampered_ciphertext_fails() {
    let store = InMemoryKeyStore::default();
    let key = store.create_key().expect("key");
    let material = store.get_key(key.key_id).expect("material");
    let engine = CryptoEngine::new(Algorithm::Aes256Gcm);
    let mut envelope = engine.encrypt(&material, b"hello").expect("encrypt");
    envelope.ciphertext[0] ^= 0xFF;
    let err = engine.decrypt(&material, &envelope).expect_err("must fail");
    assert!(matches!(err, QimemError::Decryption));
}

#[test]
fn wrong_key_id_fails() {
    let store = InMemoryKeyStore::default();
    let a = store.create_key().expect("a");
    let b = store.create_key().expect("b");
    let a_key = store.get_key(a.key_id).expect("a key");
    let b_key = store.get_key(b.key_id).expect("b key");
    let engine = CryptoEngine::new(Algorithm::Aes256Gcm);
    let envelope = engine.encrypt(&a_key, b"hello").expect("encrypt");
    let err = engine.decrypt(&b_key, &envelope).expect_err("must fail");
    assert!(matches!(err, QimemError::Decryption));
}

#[test]
fn invalid_envelope_version_fails() {
    let env = Envelope {
        version: 2,
        algorithm: Algorithm::Aes256Gcm,
        key_id: uuid::Uuid::new_v4(),
        nonce: vec![0; 12],
        ciphertext: vec![1],
        tag: vec![0; 16],
    };
    let err = env.serialize_binary().expect_err("must fail");
    assert!(matches!(err, QimemError::UnsupportedVersion(2)));
}

#[test]
fn rotation_flow() {
    let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::default());
    let key = store.create_key().expect("key");
    let before = store.get_key(key.key_id).expect("old key");
    let engine = CryptoEngine::new(Algorithm::Aes256Gcm);
    let envelope = engine.encrypt(&before, b"hello").expect("encrypt");

    let rotated = store.rotate_key(key.key_id).expect("rotate");
    let old_after = store.get_key(key.key_id).expect("old still present");
    assert!(!old_after.active);

    let old_encrypt_err = engine
        .encrypt(&old_after, b"new data")
        .expect_err("must fail");
    assert!(matches!(old_encrypt_err, QimemError::KeyInactive(_)));

    let decrypted = engine
        .decrypt(&before, &envelope)
        .expect("decrypt old payload");
    assert_eq!(decrypted, b"hello");

    let new_key = store.get_key(rotated.key_id).expect("new key");
    let wrong = engine
        .decrypt(&new_key, &envelope)
        .expect_err("cross key should fail");
    assert!(matches!(wrong, QimemError::Decryption));
}

#[test]
fn concurrent_encrypt_operations() {
    let store = Arc::new(InMemoryKeyStore::default());
    let key = store.create_key().expect("key");
    let key_material = store.get_key(key.key_id).expect("material");
    let mut handles = Vec::new();
    for _ in 0..16 {
        let key = key_material.clone();
        handles.push(std::thread::spawn(move || {
            let engine = CryptoEngine::new(Algorithm::Aes256Gcm);
            engine.encrypt(&key, b"payload").is_ok()
        }));
    }
    for h in handles {
        assert!(h.join().expect("join"));
    }
}
