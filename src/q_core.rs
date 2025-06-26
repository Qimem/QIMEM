use pyo3::prelude::*;
use pyo3::types::PyBytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use pyo3::exceptions::PyValueError;
use rand::RngCore;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit as AesKeyInit};
use aes::cipher::generic_array::GenericArray;

#[derive(thiserror::Error, Debug)]
pub enum QCoreError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

impl From<QCoreError> for PyErr {
    fn from(err: QCoreError) -> PyErr {
        PyValueError::new_err(err.to_string())
    }
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
        .map_err(|_| QCoreError::EncryptionFailed)?;
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(PyBytes::new_bound(py, &output))
}

#[pyfunction]
pub fn decrypt<'py>(py: Python<'py>, encrypted: &[u8], key: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
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
        .map_err(|_| QCoreError::DecryptionFailed)?;
    Ok(PyBytes::new_bound(py, &plaintext))
}

// Simple versions for non-Python use
pub fn encrypt_simple(message: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes for AES-256".into());
    }

    // Simple AES-256-ECB for now (you can enhance this later)
    let cipher = Aes256::new(GenericArray::from_slice(key));
    
    // Pad message to multiple of 16 bytes
    let mut padded_message = message.to_vec();
    let padding_len = 16 - (message.len() % 16);
    padded_message.extend(vec![padding_len as u8; padding_len]);
    
    let mut encrypted = Vec::new();
    for chunk in padded_message.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted.extend_from_slice(&block);
    }
    
    Ok(encrypted)
}

pub fn decrypt_simple(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes for AES-256".into());
    }

    if encrypted.len() % 16 != 0 {
        return Err("Encrypted data length must be multiple of 16".into());
    }

    let cipher = Aes256::new(GenericArray::from_slice(key));
    
    let mut decrypted = Vec::new();
    for chunk in encrypted.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted.extend_from_slice(&block);
    }
    
    // Remove padding
    if let Some(&padding_len) = decrypted.last() {
        if padding_len > 0 && padding_len <= 16 {
            decrypted.truncate(decrypted.len() - padding_len as usize);
        }
    }
    
    Ok(decrypted)
}