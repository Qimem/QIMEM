use crate::q_keygen::derive_key;
use crate::q_core::{decrypt, encrypt, decrypt_simple, encrypt_simple};
use crate::tests::init_python;
use pyo3::Python;
use pyo3::types::PyBytesMethods;

#[test]
fn test_encrypt_decrypt() {
    init_python();
    Python::with_gil(|py| {
        let (key, _) = derive_key(py, "password", None, None).unwrap();
        let data = b"hello world";
        let encrypted = encrypt(py, data, key.as_bytes()).unwrap();
        let decrypted = decrypt(py, encrypted.as_bytes(), key.as_bytes()).unwrap();
        assert_eq!(data, decrypted.as_bytes());
    });
}

#[test]
fn test_key_derivation() {
    init_python();
    Python::with_gil(|py| {
        let (key1, salt1) = derive_key(py, "password", Some("saltphrase"), None).unwrap();
        let (key2, salt2) = derive_key(py, "password", Some("saltphrase"), None).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(salt1.as_bytes(), salt2.as_bytes());
    });
}

#[test]
fn test_encrypt_decrypt_simple() {
    let (key, _) = crate::q_keygen::derive_key_simple("password", None, None).unwrap();
    let data = b"hello secure world";
    let encrypted = encrypt_simple(data, &key).unwrap();
    let decrypted = decrypt_simple(&encrypted, &key).unwrap();
    assert_eq!(data, decrypted.as_slice());
}
