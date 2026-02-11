#![allow(dead_code)]
#![allow(clippy::useless_conversion)]
// Needed for PyO3 macro-generated signatures that trigger Clippy false positives in this crate.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::RngCore;

#[derive(thiserror::Error, Debug)]
pub enum QCoreError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

#[pyfunction]
pub fn encrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let key_array: [u8; 32] = key
        .try_into()
        .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let cipher = ChaCha20Poly1305::new(&key_array.into());
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| PyValueError::new_err(QCoreError::EncryptionFailed.to_string()))?;
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(PyBytes::new_bound(py, &output))
}

#[pyfunction]
pub fn decrypt<'py>(
    py: Python<'py>,
    encrypted: &[u8],
    key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key_array: [u8; 32] = key
        .try_into()
        .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    if encrypted.len() < 12 {
        return Err(PyValueError::new_err("Invalid encrypted data"));
    }
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];
    let cipher = ChaCha20Poly1305::new(&key_array.into());
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| PyValueError::new_err(QCoreError::DecryptionFailed.to_string()))?;
    Ok(PyBytes::new_bound(py, &plaintext))
}

// Simple versions for non-Python use
pub fn encrypt_simple(message: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".into());
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), message)
        .map_err(|_| QCoreError::EncryptionFailed)?;
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt_simple(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".into());
    }
    if encrypted.len() < 12 {
        return Err("Encrypted data length must be at least 12 bytes".into());
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)?;
    let (nonce, ciphertext) = encrypted.split_at(12);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| QCoreError::DecryptionFailed)?;
    Ok(plaintext)
}
