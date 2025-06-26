use pyo3::prelude::*;
use pyo3::types::PyBytes;
use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;
use sha2::{Sha256, Digest};
use pyo3::exceptions::PyValueError;

#[derive(thiserror::Error, Debug)]
pub enum KeyGenError {
    #[error("Invalid salt: {0}")]
    SaltInvalid(String),
    #[error("Hash error: {0}")]
    HashError(String),
}

impl From<KeyGenError> for PyErr {
    fn from(err: KeyGenError) -> PyErr {
        PyValueError::new_err(err.to_string())
    }
}

#[pyfunction]
#[pyo3(signature = (password, salt_phrase=None))]
pub fn derive_key<'py>(py: Python<'py>, password: &str, salt_phrase: Option<&str>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let mut salt = [0u8; 16];
    if let Some(phrase) = salt_phrase {
        if phrase.len() < 8 || !phrase.chars().all(|c| c.is_alphanumeric()) {
            return Err(PyValueError::new_err("Salt must be 8+ alphanumeric chars"));
        }
        let mut hasher = Sha256::new();
        hasher.update(phrase.as_bytes());
        salt.copy_from_slice(&hasher.finalize()[..16]);
    } else {
        rand::thread_rng().fill_bytes(&mut salt);
    }
    let params = Params::new(32768, 4, 1, Some(32)).map_err(|e| KeyGenError::HashError(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| KeyGenError::HashError(e.to_string()))?;
    Ok((PyBytes::new_bound(py, &key), PyBytes::new_bound(py, &salt)))
}

// Simple version for non-Python use
pub fn derive_key_simple(password: &str, salt_phrase: Option<&str>) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut salt = [0u8; 16];
    if let Some(phrase) = salt_phrase {
        if phrase.len() < 8 || !phrase.chars().all(|c| c.is_alphanumeric()) {
            return Err("Salt must be 8+ alphanumeric chars".into());
        }
        let mut hasher = Sha256::new();
        hasher.update(phrase.as_bytes());
        salt.copy_from_slice(&hasher.finalize()[..16]);
    } else {
        rand::thread_rng().fill_bytes(&mut salt);
    }
    
    let params = Params::new(32768, 4, 1, Some(32))
        .map_err(|e| format!("Params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("Hash error: {}", e))?;
    
    Ok((key.to_vec(), salt.to_vec()))
}