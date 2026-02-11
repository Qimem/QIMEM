use crate::signing::{generate_keypair, sign_message, verify_signature};
use crate::tests::init_python;
use pyo3::types::PyBytesMethods;
use pyo3::Python;

#[test]
fn test_sign_verify() {
    init_python();
    Python::with_gil(|py| {
        let (public_key, secret_key) = generate_keypair(py).expect("Key generation failed");
        let message = b"Test message";
        let signature_vec =
            sign_message(py, secret_key.as_bytes(), message).expect("Signing failed");

        let signature: [u8; 64] = signature_vec
            .as_bytes()
            .try_into()
            .expect("Invalid signature length");

        let result = verify_signature(py, public_key.as_bytes(), message, &signature)
            .expect("Verification failed");

        assert!(result, "Signature verification failed");
    });
}
