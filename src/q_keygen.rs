use argon2::{Algorithm, Argon2, Params, Version, PasswordHasher};
use rand::{rngs::ThreadRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64;
use base64::Engine;
use argon2::password_hash::SaltString;

#[derive(Error, Debug)]
pub enum KeyGenError {
    #[error("Invalid salt: {0}")]
    SaltInvalid(String),
    #[error("Hashing failed: {0}")]
    HashError(String),
}

pub fn derive_key(password: &str, salt_phrase: Option<&str>) -> Result<([u8; 32], [u8; 16]), KeyGenError> {
    let mut salt = [0u8; 16];
    if let Some(phrase) = salt_phrase {
        if phrase.len() < 8 {
            return Err(KeyGenError::SaltInvalid("Salt must be 8+ chars".to_string()));
        }
        let mut hasher = Sha256::new();
        hasher.update(phrase.as_bytes());
        salt.copy_from_slice(&hasher.finalize()[..16]);
    } else {
        ThreadRng::default().fill_bytes(&mut salt);
    }
    let salt_b64 = BASE64.encode(&salt);
    let salt_ref = SaltString::from_b64(&salt_b64).map_err(|e| KeyGenError::SaltInvalid(e.to_string()))?;
    let params = Params::new(32768, 4, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt_ref)
        .map_err(|e| KeyGenError::HashError(e.to_string()))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.hash.unwrap().as_bytes());
    Ok((key, salt))
}