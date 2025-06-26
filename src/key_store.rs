use pyo3::prelude::*;
use pyo3::types::PyBytesMethods;
use crate::q_keygen::derive_key;
use crate::q_core::{encrypt, decrypt, QCoreError};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use bincode;
use chrono::Utc;
use pyo3::exceptions::{PyValueError, PyIOError};

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
}

#[pymethods]
impl KeyStore {
    #[new]
    pub fn new(py: Python<'_>, path: &str, master_password: &str) -> PyResult<Self> {
        let (master_key_bound, _) = derive_key(py, master_password, None)?;
        let master_key: [u8; 32] = master_key_bound.as_bytes()
            .try_into()
            .map_err(|_| PyValueError::new_err("Master key must be 32 bytes"))?;
        let keys = if Path::new(path).exists() {
            let mut encrypted_file = File::open(path).map_err(|e| PyIOError::new_err(e.to_string()))?;
            let mut encrypted_data = Vec::new();
            encrypted_file.read_to_end(&mut encrypted_data).map_err(|e| PyIOError::new_err(e.to_string()))?;
            let decrypted_bound = decrypt(py, &encrypted_data, &master_key)?;
            let decrypted_data = decrypted_bound.as_bytes();
            bincode::deserialize(decrypted_data).map_err(|e| PyValueError::new_err(e.to_string()))?
        } else {
            HashMap::new()
        };
        Ok(KeyStore {
            keys,
            path: path.to_string(),
            master_key,
        })
    }

    pub fn store_key(&mut self, py: Python<'_>, id: &str, key: &[u8]) -> PyResult<()> {
        let key_array: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
        let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let full_id = format!("{}_{}", id, timestamp);
        self.keys.insert(full_id, key_array);
        let serialized_data = bincode::serialize(&self.keys).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let encrypted_bound = encrypt(py, &serialized_data, &self.master_key)?;
        let encrypted_data = encrypted_bound.as_bytes();
        fs::write(&self.path, encrypted_data).map_err(|e| PyIOError::new_err(e.to_string()))?;
        Ok(())
    }

    pub fn retrieve_key(&self, _py: Python<'_>, id: &str) -> PyResult<Option<Vec<u8>>> {
        Ok(self.keys.get(id).map(|k| k.to_vec()))
    }
}