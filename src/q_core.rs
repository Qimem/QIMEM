use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QCoreError {
    #[error("Encryption failed: {0}")]
    Encrypt(String),
    #[error("Decryption failed: {0}")]
    Decrypt(String),
}

pub fn encrypt(data: &[u8], key: &[u8; 32], salt: &[u8; 16]) -> Result<Vec<u8>, QCoreError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| QCoreError::Encrypt(e.to_string()))?;
    Ok([salt, &nonce[..], &ciphertext[..]].concat())
}

pub fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, QCoreError> {
    if ciphertext.len() < 28 {
        return Err(QCoreError::Decrypt("Ciphertext too short".to_string()));
    }
    let (_salt, rest) = ciphertext.split_at(16); // Salt not used in decrypt
    let (nonce, data) = rest.split_at(12);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, data)
        .map_err(|e| QCoreError::Decrypt(e.to_string()))
}