#[cfg(test)]
mod tests {
    use crate::cipher::*;
    use crate::key_derivation::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = derive_key("password", "AxumObelisk2025")
            .expect("Key derivation failed");
        let data = b"Hello, Qimem!";
        let encrypted = encrypt(data, &key).expect("Encryption failed");
        let decrypted = decrypt(&encrypted, &key).expect("Decryption failed");
        assert_eq!(decrypted, data);
    }
}