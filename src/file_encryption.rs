use std::fs::{self, File};
use std::io::Write;
use crate::q_core::{encrypt, decrypt, QCoreError};
use pyo3::prelude::*;
use pyo3::types::PyBytesMethods;
use pyo3::exceptions::PyValueError;

#[derive(thiserror::Error, Debug)]
pub enum FileEncryptionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encryption error: {0}")]
    Encryption(#[from] QCoreError),
}

#[pyfunction]
pub fn encrypt_file<'py>(
    py: Python<'py>,
    input_path: &str,
    output_path: &str,
    key: Vec<u8>,
    salt: Vec<u8>
) -> PyResult<()> {
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let _salt_array: [u8; 16] = salt.try_into()
        .map_err(|_| PyValueError::new_err("Salt must be 16 bytes"))?;
    let data = fs::read(input_path).map_err(|e| FileEncryptionError::Io(e))?;
    let encrypted_data = encrypt(py, &data, &key_array)?;
    fs::write(output_path, encrypted_data.as_bytes()).map_err(|e| FileEncryptionError::Io(e))?;
    Ok(())
}

#[pyfunction]
pub fn decrypt_file<'py>(
    py: Python<'py>,
    input_path: &str,
    output_path: &str,
    key: Vec<u8>
) -> PyResult<()> {
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let encrypted_data = fs::read(input_path).map_err(|e| FileEncryptionError::Io(e))?;
    let decrypted_data = decrypt(py, &encrypted_data, &key_array)?;
    let mut output_file = File::create(output_path).map_err(|e| FileEncryptionError::Io(e))?;
    output_file.write_all(decrypted_data.as_bytes()).map_err(|e| FileEncryptionError::Io(e))?;
    Ok(())
}