use pyo3::prelude::*;
use pyo3::types::PyBytes;
use totp_rs::{Algorithm, TOTP};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use rand::RngCore;
use pyo3::exceptions::PyValueError;

#[pyfunction]
pub fn generate_totp_secret<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
    let mut bytes = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut bytes);
    let secret = BASE64_STANDARD.encode(bytes);
    Ok(PyBytes::new_bound(py, secret.as_bytes()))
}

#[pyfunction]
pub fn get_totp_code<'py>(py: Python<'py>, secret: &str) -> PyResult<Bound<'py, PyBytes>> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        BASE64_STANDARD.decode(secret).map_err(|_| PyValueError::new_err("Invalid secret"))?,
    ).map_err(|_| PyValueError::new_err("Failed to create TOTP"))?;
    let code = totp.generate_current().map_err(|_| PyValueError::new_err("Failed to generate TOTP code"))?;
    Ok(PyBytes::new_bound(py, code.as_bytes()))
}

#[pyfunction]
pub fn verify_totp_code(secret: &str, code: &str) -> PyResult<bool> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        BASE64_STANDARD.decode(secret).map_err(|_| PyValueError::new_err("Invalid secret"))?,
    ).map_err(|_| PyValueError::new_err("Failed to create TOTP"))?;
    Ok(totp.check_current(code).map_err(|_| PyValueError::new_err("Failed to verify TOTP code"))?)
}