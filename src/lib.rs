use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyValueError;

pub mod key_store;
pub mod q_keygen;
pub mod q_core;
pub mod file_encryption;
pub mod signing;
pub mod tests;
pub mod utils;
pub mod totp;
pub mod obfuscation;
pub mod bucketing;

use key_store::{KeyStore, KeyStoreError};
use file_encryption::FileEncryptionError;

impl From<KeyStoreError> for PyErr {
    fn from(err: KeyStoreError) -> PyErr {
        PyValueError::new_err(err.to_string())
    }
}

impl From<FileEncryptionError> for PyErr {
    fn from(err: FileEncryptionError) -> PyErr {
        PyValueError::new_err(err.to_string())
    }
}

#[pymodule]
fn qimem(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_derive_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(py_encrypt_file, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_file, m)?)?;
    m.add_function(wrap_pyfunction!(py_generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(py_sign_message, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(totp::generate_totp_secret, m)?)?;
    m.add_function(wrap_pyfunction!(totp::get_totp_code, m)?)?;
    m.add_function(wrap_pyfunction!(totp::verify_totp_code, m)?)?;
    m.add_function(wrap_pyfunction!(obfuscation::generate_whitepaper_outline, m)?)?;
    m.add_function(wrap_pyfunction!(obfuscation::anti_debug_check, m)?)?;
    m.add_function(wrap_pyfunction!(bucketing::bucket_sensitive_data, m)?)?;
    m.add_class::<PyKeyStore>()?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (password, salt_phrase=None))]
pub fn py_derive_key(py: Python<'_>, password: String, salt_phrase: Option<String>) -> PyResult<(Bound<'_, PyBytes>, Bound<'_, PyBytes>)> {
    q_keygen::derive_key(py, &password, salt_phrase.as_deref())
}

#[pyfunction]
pub fn py_encrypt(py: Python<'_>, data: Vec<u8>, key: Vec<u8>) -> PyResult<Bound<'_, PyBytes>> {
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    q_core::encrypt(py, &data, &key_array)
}

#[pyfunction]
pub fn py_decrypt(py: Python<'_>, encrypted: Vec<u8>, key: Vec<u8>) -> PyResult<Bound<'_, PyBytes>> {
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    q_core::decrypt(py, &encrypted, &key_array)
}

#[pyfunction]
fn py_encrypt_file(py: Python<'_>, input_path: String, output_path: String, key: Vec<u8>, salt: Vec<u8>) -> PyResult<()> {
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let salt_array: [u8; 16] = salt.try_into()
        .map_err(|_| PyValueError::new_err("Salt must be 16 bytes"))?;
    file_encryption::encrypt_file(py, &input_path, &output_path, key_array.to_vec(), salt_array.to_vec())?;
    Ok(())
}

#[pyfunction]
fn py_decrypt_file(py: Python<'_>, input_path: String, output_path: String, key: Vec<u8>) -> PyResult<()> {
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    file_encryption::decrypt_file(py, &input_path, &output_path, key_array.to_vec())?;
    Ok(())
}

#[pyfunction]
fn py_generate_keypair(py: Python<'_>) -> PyResult<(Bound<'_, PyBytes>, Bound<'_, PyBytes>)> {
    signing::generate_keypair(py)
}

#[pyfunction]
fn py_sign_message(py: Python<'_>, secret_key: Vec<u8>, message: Vec<u8>) -> PyResult<Bound<'_, PyBytes>> {
    let secret_key_array: [u8; 32] = secret_key.try_into()
        .map_err(|_| PyValueError::new_err("Secret key must be 32 bytes"))?;
    signing::sign_message(py, &secret_key_array, &message)
}

#[pyfunction]
fn py_verify_signature(py: Python<'_>, public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
    let public_key_array: [u8; 32] = public_key.try_into()
        .map_err(|_| PyValueError::new_err("Public key must be 32 bytes"))?;
    let signature_array: [u8; 64] = signature.try_into()
        .map_err(|_| PyValueError::new_err("Signature must be 64 bytes"))?;
    signing::verify_signature(py, &public_key_array, &message, &signature_array)
}

#[pyclass(name = "KeyStore")]
pub struct PyKeyStore {
    inner: KeyStore,
}

#[pymethods]
impl PyKeyStore {
    #[new]
    fn new(py: Python<'_>, _path: String, master_password: String) -> PyResult<Self> {
        let inner = KeyStore::new(py, &_path, &master_password)?;
        Ok(PyKeyStore { inner })
    }

    fn store_key(&mut self, py: Python<'_>, id: String, key: Vec<u8>) -> PyResult<()> {
        let key_array: [u8; 32] = key.try_into()
            .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
        self.inner.store_key(py, &id, &key_array)?;
        Ok(())
    }

    fn retrieve_key(&self, py: Python<'_>, id: String) -> PyResult<Option<Vec<u8>>> {
        self.inner.retrieve_key(py, &id)
    }
}