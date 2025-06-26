use pyo3::prelude::*;
use pyo3::types::PyBytes;
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use pyo3::exceptions::PyValueError;

#[pyfunction]
pub fn generate_keypair<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    Ok((
        PyBytes::new_bound(py, verifying_key.as_bytes()),
        PyBytes::new_bound(py, signing_key.as_bytes()),
    ))
}

#[pyfunction]
pub fn sign_message<'py>(py: Python<'py>, secret_key: &[u8], message: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let secret_key_array: [u8; 32] = secret_key.try_into()
        .map_err(|_| PyValueError::new_err("Secret key must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&secret_key_array);
    let signature = signing_key.sign(message);
    Ok(PyBytes::new_bound(py, signature.to_bytes().as_ref()))
}

#[pyfunction]
pub fn verify_signature<'py>(_py: Python<'py>, public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    let public_key_array: [u8; 32] = public_key.try_into()
        .map_err(|_| PyValueError::new_err("Public key must be 32 bytes"))?;
    let signature_array: [u8; 64] = signature.try_into()
        .map_err(|_| PyValueError::new_err("Signature must be 64 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| PyValueError::new_err("Invalid public key"))?;
    let signature = Signature::try_from(signature_array)
        .map_err(|_| PyValueError::new_err("Invalid signature"))?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}