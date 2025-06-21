use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QCoreError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, QCoreError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]); // Simplified nonce for testing
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|_| QCoreError::EncryptionFailed)?;
    Ok(ciphertext)
}

pub fn decrypt(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, QCoreError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let plaintext = cipher.decrypt(nonce, encrypted)
        .map_err(|_| QCoreError::DecryptionFailed)?;
    Ok(plaintext)
}