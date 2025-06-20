use pyo3::prelude::{pymodule, pyfunction, PyModule, PyResult, Python};
use pyo3::{wrap_pyfunction_bound, PyErr, Bound, Py};
use pyo3::types::{PyModuleMethods, PyBytes};

#[cfg(test)]
mod tests;
pub mod cipher;
pub mod key_derivation;
pub mod signing;
pub mod file_encryption;
pub mod utils;

#[pymodule]
fn qimem(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction_bound!(encrypt, py)?)?;
    m.add_function(wrap_pyfunction_bound!(decrypt, py)?)?;
    m.add_function(wrap_pyfunction_bound!(derive_key, py)?)?;
    m.add_function(wrap_pyfunction_bound!(encrypt_file, py)?)?;
    m.add_function(wrap_pyfunction_bound!(decrypt_file, py)?)?;
    m.add_function(wrap_pyfunction_bound!(generate_keypair, py)?)?;
    m.add_function(wrap_pyfunction_bound!(sign_message, py)?)?;
    m.add_function(wrap_pyfunction_bound!(verify_signature, py)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

#[pyfunction]
fn encrypt(py: Python<'_>, data: Vec<u8>, key: Vec<u8>) -> PyResult<Py<PyBytes>> {
    let key_array: [u8; 32] = key.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
    let result = cipher::encrypt(&data, &key_array)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &result).into())
}

#[pyfunction]
fn decrypt(py: Python<'_>, ciphertext: Vec<u8>, key: Vec<u8>) -> PyResult<Py<PyBytes>> {
    let key_array: [u8; 32] = key.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
    let result = cipher::decrypt(&ciphertext, &key_array)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &result).into())
}

#[pyfunction]
fn derive_key(password: String, salt_phrase: String) -> PyResult<Vec<u8>> {
    key_derivation::derive_key(&password, &salt_phrase)
        .map(|key| key.to_vec())
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

#[pyfunction]
fn encrypt_file(input_path: String, output_path: String, key: Vec<u8>) -> PyResult<()> {
    let key_array: [u8; 32] = key.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
    file_encryption::encrypt_file(&input_path, &output_path, &key_array)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))
}

#[pyfunction]
fn decrypt_file(input_path: String, output_path: String, key: Vec<u8>) -> PyResult<()> {
    let key_array: [u8; 32] = key.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
    file_encryption::decrypt_file(&input_path, &output_path, &key_array)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string()))
}

#[pyfunction]
fn generate_keypair() -> PyResult<(Vec<u8>, Vec<u8>)> {
    use ring::signature::KeyPair; // Import trait for public_key()
    let (keypair, pkcs8_bytes) = signing::generate_keypair();
    let public_key = keypair.public_key().as_ref(); // Extract public key bytes
    Ok((public_key.to_vec(), pkcs8_bytes))
}

#[pyfunction]
fn sign_message(secret_key: Vec<u8>, message: Vec<u8>) -> PyResult<Vec<u8>> {
    let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(&secret_key)
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid secret key"))?;
    let signature = keypair.sign(&message);
    Ok(signature.as_ref().to_vec())
}

#[pyfunction]
fn verify_signature(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
    let public_key_array: [u8; 32] = public_key
        .try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Public key must be 32 bytes"))?;
    let signature_array: [u8; 64] = signature
        .try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Signature must be 64 bytes"))?;
    Ok(signing::verify_signature(&public_key_array, &message, &signature_array))
}