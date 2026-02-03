use crate::q_keygen::derive_key;
use crate::tests::init_python;
use pyo3::Python;
use pyo3::types::PyBytesMethods;

#[test]
fn test_user_salt() {
    init_python();
    Python::with_gil(|py| {
        let (key1, salt1) = derive_key(py, "password", Some("saltphrase")).unwrap();
        let (key2, salt2) = derive_key(py, "password", Some("saltphrase")).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(salt1.as_bytes(), salt2.as_bytes());
    });
}

#[test]
fn test_random_salt() {
    init_python();
    Python::with_gil(|py| {
        let (key1, salt1) = derive_key(py, "password", None).unwrap();
        let (key2, salt2) = derive_key(py, "password", None).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_ne!(salt1.as_bytes(), salt2.as_bytes());
    });
}

#[test]
fn test_invalid_salt() {
    init_python();
    Python::with_gil(|py| {
        let (key1, salt1) = derive_key(py, "password", Some("saltphrase1")).unwrap();
        let (key2, salt2) = derive_key(py, "password", Some("saltphrase2")).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_ne!(salt1.as_bytes(), salt2.as_bytes());
    });
}
