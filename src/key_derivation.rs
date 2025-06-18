use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use thiserror::Error;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

#[derive(Error, Debug)]
pub enum KeyDerivationError {
    #[error("Invalid salt: {0}")]
    SaltInvalid(String),
    #[error("Hashing failed: {0}")]
    HashError(String),
}

pub fn derive_key(password: &str, salt_phrase: &str) -> Result<[u8; 32], KeyDerivationError> {
    let salt_bytes = salt_phrase.as_bytes();
    let salt_b64 = BASE64.encode(salt_bytes);
    let salt = SaltString::from_b64(&salt_b64)
        .map_err(|e| KeyDerivationError::SaltInvalid(e.to_string()))?;
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| KeyDerivationError::HashError(e.to_string()))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash.hash.unwrap().as_bytes()[..32]);
    Ok(key)
}