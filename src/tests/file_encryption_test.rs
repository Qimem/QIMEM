use crate::q_keygen::derive_key;
use crate::file_encryption::{encrypt_file, decrypt_file};
use crate::tests::init_python;
use pyo3::Python;
use pyo3::types::PyBytesMethods;
use std::fs;
use std::io::Read;

#[test]
fn test_encrypt_decrypt_file() {
    init_python();
    Python::with_gil(|py| {
        let (key, salt) = derive_key(py, "password", None, None).unwrap();
        let input_path = "test_input.txt";
        let encrypted_path = "test_encrypted.bin";
        let decrypted_path = "test_decrypted.txt";
        let data = b"hello file encryption";

        fs::write(input_path, data).unwrap();
        encrypt_file(
            py,
            input_path,
            encrypted_path,
            key.as_bytes().to_vec(),
            salt.as_bytes().to_vec(),
        )
        .unwrap();
        decrypt_file(py, encrypted_path, decrypted_path, key.as_bytes().to_vec()).unwrap();

        let mut decrypted_data = Vec::new();
        fs::File::open(decrypted_path).unwrap().read_to_end(&mut decrypted_data).unwrap();

        assert_eq!(data, decrypted_data.as_slice());

        fs::remove_file(input_path).unwrap();
        fs::remove_file(encrypted_path).unwrap();
        fs::remove_file(decrypted_path).unwrap();
    });
}
