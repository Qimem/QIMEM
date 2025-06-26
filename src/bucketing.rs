use regex::Regex;
use std::fs::File;
use std::io::Write;
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

#[pyfunction]
pub fn bucket_sensitive_data(data: &str, bucket_path: &str) -> PyResult<()> {
    let ssn_re = Regex::new(r"\d{3}-\d{2}-\d{4}").map_err(|e| PyValueError::new_err(format!("Regex error: {}", e)))?;
    if ssn_re.is_match(data) {
        let mut file = File::create(bucket_path)
            .map_err(|e| PyValueError::new_err(format!("Failed to write to bucket: {}", e)))?;
        writeln!(file, "Sensitive data: {}", data)?;
    }
    Ok(())
}