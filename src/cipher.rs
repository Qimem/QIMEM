use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Encryption failed: {0}")]
    Encrypt(String),
    #[error("Decryption failed: {0}")]
    Decrypt(String),
}

pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CipherError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| CipherError::Encrypt(e.to_string()))?;
    Ok([&nonce[..], &ciphertext[..]].concat())
}

pub fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CipherError> {
    if ciphertext.len() < 12 {
        return Err(CipherError::Decrypt("Ciphertext too short".to_string()));
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let (nonce, data) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, data)
        .map_err(|e| CipherError::Decrypt(e.to_string()))
}