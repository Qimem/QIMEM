use std::fs::{self, File};
use std::io::{self, Write};
use crate::q_core::{encrypt, decrypt, QCoreError};

pub fn encrypt_file(input_path: &str, output_path: &str, key: &[u8; 32], salt: &[u8; 16]) -> io::Result<()> {
    let data = fs::read(input_path)?;
    let encrypted = encrypt(&data, key, salt).map_err(|e: QCoreError| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let mut file = File::create(output_path)?;
    file.write_all(&encrypted)?;
    Ok(())
}

pub fn decrypt_file(input_path: &str, output_path: &str, key: &[u8; 32]) -> io::Result<()> {
    let ciphertext = fs::read(input_path)?;
    let decrypted = decrypt(&ciphertext, key).map_err(|e: QCoreError| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let mut file = File::create(output_path)?;
    file.write_all(&decrypted)?;
    Ok(())
}