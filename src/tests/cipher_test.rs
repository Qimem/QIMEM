use crate::q_keygen::derive_key;
use crate::q_core::{encrypt, decrypt};

#[test]
fn test_encrypt_decrypt() {
    let (key, _) = derive_key("password", None).unwrap();
    let data = b"hello world";
    let encrypted = encrypt(data, &key).unwrap();
    let decrypted = decrypt(&encrypted, &key).unwrap();
    assert_eq!(data, decrypted.as_slice());
}

#[test]
fn test_key_derivation() {
    let (key1, salt1) = derive_key("password", Some("salt")).unwrap();
    let (key2, salt2) = derive_key("password", Some("salt")).unwrap();
    assert_eq!(key1, key2);
    assert_eq!(salt1, salt2);
}