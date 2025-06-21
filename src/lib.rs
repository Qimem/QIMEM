use pyo3::prelude::*;
use pyo3::types::{PyModule, PyBytes};

pub mod q_keygen;
pub mod q_core;
pub mod file_encryption;
pub mod signing;

use q_keygen::derive_key;
use q_core::{encrypt, decrypt};
use file_encryption::{encrypt_file, decrypt_file};
use signing::{generate_keypair, sign_message, verify_signature};

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
    m.add("__version__", "0.1.0")?;
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (password, salt_phrase=None))]
fn py_derive_key(py: Python<'_>, password: String, salt_phrase: Option<String>) -> PyResult<(Bound<'_, PyBytes>, Bound<'_, PyBytes>)> {
    let (key, salt) = derive_key(&password, salt_phrase.as_deref())
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok((PyBytes::new_bound(py, &key), PyBytes::new_bound(py, &salt)))
}

#[pyfunction]
fn py_encrypt(py: Python<'_>, data: Vec<u8>, key: Vec<u8>) -> PyResult<Bound<'_, PyBytes>> {
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
    let encrypted = encrypt(&data, &key_array)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &encrypted))
}

#[pyfunction]
fn py_decrypt(py: Python<'_>, encrypted: Vec<u8>, key: Vec<u8>) -> PyResult<Bound<'_, PyBytes>> {
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
    let decrypted = decrypt(&encrypted, &key_array)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &decrypted))
}

#[pyfunction]
fn py_encrypt_file(input_path: String, output_path: String, key: Vec<u8>, salt: Vec<u8>) -> PyResult<()> {
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
    let salt_array: [u8; 16] = salt.try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Salt must be 16 bytes"))?;
    encrypt_file(&input_path, &output_path, &key_array, &salt_array)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
    Ok(())
}

#[pyfunction]
fn py_decrypt_file(input_path: String, output_path: String, key: Vec<u8>) -> PyResult<()> {
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
    decrypt_file(&input_path, &output_path, &key_array)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))?;
    Ok(())
}

#[pyfunction]
fn py_generate_keypair(py: Python<'_>) -> PyResult<(Bound<'_, PyBytes>, Bound<'_, PyBytes>)> {
    let (public_key, secret_key) = generate_keypair()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok((PyBytes::new_bound(py, &public_key), PyBytes::new_bound(py, &secret_key)))
}

#[pyfunction]
fn py_sign_message(py: Python<'_>, secret_key: Vec<u8>, message: Vec<u8>) -> PyResult<Bound<'_, PyBytes>> {
    let secret_key_array: [u8; 32] = secret_key.try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Secret key must be 32 bytes"))?;
    let signature = sign_message(&secret_key_array, &message)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &signature))
}

#[pyfunction]
fn py_verify_signature(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
    let public_key_array: [u8; 32] = public_key.try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Public key must be 32 bytes"))?;
    let signature_array: [u8; 64] = signature.try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Signature must be 64 bytes"))?;
    let result = verify_signature(&public_key_array, &message, &signature_array)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    include!("tests/mod.rs");
}