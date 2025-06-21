use crate::file_encryption::*;
use crate::q_keygen::*;
use tempfile::NamedTempFile;
use std::fs;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_file() {
        let (key, salt) = derive_key("password", None)
            .expect("Key derivation failed");
        let input = NamedTempFile::new().unwrap();
        let output = NamedTempFile::new().unwrap();
        let decrypted = NamedTempFile::new().unwrap();

        fs::write(&input, b"Secret file").unwrap();
        encrypt_file(input.path().to_str().unwrap(), output.path().to_str().unwrap(), &key, &salt)
            .expect("File encryption failed");
        decrypt_file(output.path().to_str().unwrap(), decrypted.path().to_str().unwrap(), &key)
            .expect("File decryption failed");

        let content = fs::read(decrypted.path()).unwrap();
        assert_eq!(content, b"Secret file");
    }
}