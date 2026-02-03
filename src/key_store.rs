use pyo3::prelude::*;
use pyo3::types::PyBytesMethods;
use crate::q_core::{encrypt, decrypt, QCoreError};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use bincode;
use pyo3::exceptions::{PyValueError, PyIOError};
use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;

#[derive(thiserror::Error, Debug)]
pub enum KeyStoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("Encryption error: {0}")]
    Encryption(#[from] QCoreError),
    #[error("Invalid key")]
    InvalidKey,
}

#[pyclass]
pub struct KeyStore {
    keys: HashMap<String, [u8; 32]>,
    path: String,
    master_key: [u8; 32],
    salt: [u8; 16],
}

#[pymethods]
impl KeyStore {
    #[new]
    pub fn new(py: Python<'_>, path: &str, master_password: &str) -> PyResult<Self> {
        let (keys, master_key, salt) = if Path::new(path).exists() {
            let mut encrypted_file = File::open(path).map_err(|e| PyIOError::new_err(e.to_string()))?;
            let mut encrypted_data = Vec::new();
            encrypted_file.read_to_end(&mut encrypted_data).map_err(|e| PyIOError::new_err(e.to_string()))?;
            if encrypted_data.len() < 16 {
                return Err(PyValueError::new_err("Invalid keystore data"));
            }
            let salt: [u8; 16] = encrypted_data[..16]
                .try_into()
                .map_err(|_| PyValueError::new_err("Invalid keystore salt"))?;
            let master_key = derive_master_key(master_password, &salt)?;
            let decrypted_bound = decrypt(py, &encrypted_data[16..], &master_key)?;
            let decrypted_data = decrypted_bound.as_bytes();
            let keys = bincode::deserialize(decrypted_data).map_err(|e| PyValueError::new_err(e.to_string()))?;
            (keys, master_key, salt)
        } else {
            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            let master_key = derive_master_key(master_password, &salt)?;
            (HashMap::new(), master_key, salt)
        };
        Ok(KeyStore {
            keys,
            path: path.to_string(),
            master_key,
            salt,
        })
    }

    pub fn store_key(&mut self, py: Python<'_>, id: &str, key: &[u8]) -> PyResult<()> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
        self.keys.insert(id.to_string(), key_array);
        let serialized_data = bincode::serialize(&self.keys).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let encrypted_bound = encrypt(py, &serialized_data, &self.master_key)?;
        let mut encrypted_data = Vec::with_capacity(self.salt.len() + encrypted_bound.as_bytes().len());
        encrypted_data.extend_from_slice(&self.salt);
        encrypted_data.extend_from_slice(encrypted_bound.as_bytes());
        fs::write(&self.path, encrypted_data).map_err(|e| PyIOError::new_err(e.to_string()))?;
        Ok(())
    }

    pub fn retrieve_key(&self, _py: Python<'_>, id: &str) -> PyResult<Option<Vec<u8>>> {
        Ok(self.keys.get(id).map(|k| k.to_vec()))
    }
}

fn derive_master_key(master_password: &str, salt: &[u8; 16]) -> PyResult<[u8; 32]> {
    let params = Params::new(32768, 4, 1, Some(32))
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(key)
}
