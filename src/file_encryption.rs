use std::fs::{self, File};
use std::io::{Read, Write};
use thiserror::Error;
use crate::q_core::{encrypt, decrypt, QCoreError};

#[derive(Error, Debug)]
pub enum FileEncryptionError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Encryption error: {0}")]
    EncryptionError(#[from] QCoreError),
}

pub fn encrypt_file(input_path: &str, output_path: &str, key: &[u8; 32], salt: &[u8; 16]) -> Result<(), FileEncryptionError> {
    let mut file = File::open(input_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let encrypted = encrypt(&data, key)?;
    let mut output = File::create(output_path)?;
    output.write_all(&[&salt[..], &encrypted].concat())?;
    Ok(())
}

pub fn decrypt_file(input_path: &str, output_path: &str, key: &[u8; 32]) -> Result<(), FileEncryptionError> {
    let mut file = File::open(input_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let decrypted = decrypt(&data[16..], key)?; // Skip salt
    fs::write(output_path, decrypted)?;
    Ok(())
}