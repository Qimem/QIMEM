#[cfg(test)]
mod tests {
    use crate::file_encryption::*;
    use crate::key_derivation::*;
    use tempfile::NamedTempFile;
    use std::fs;

    #[test]
    fn test_encrypt_decrypt_file() {
        let key = derive_key("password", "AxumObelisk2025")
            .expect("Key derivation failed");
        let input = NamedTempFile::new().unwrap();
        let output = NamedTempFile::new().unwrap();
        let decrypted = NamedTempFile::new().unwrap();

        fs::write(&input, b"Secret file").unwrap();
        encrypt_file(input.path().to_str().unwrap(), output.path().to_str().unwrap(), &key)
            .expect("File encryption failed");
        decrypt_file(output.path().to_str().unwrap(), decrypted.path().to_str().unwrap(), &key)
            .expect("File decryption failed");

        let content = fs::read(decrypted.path()).unwrap();
        assert_eq!(content, b"Secret file");
    }
}