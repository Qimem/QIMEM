use crate::q_keygen::derive_key;
use crate::file_encryption::{encrypt_file, decrypt_file};
use std::fs;
use std::io::Read;

#[test]
fn test_encrypt_decrypt_file() {
    let (key, salt) = derive_key("password", None).unwrap();
    let input_path = "test_input.txt";
    let encrypted_path = "test_encrypted.bin";
    let decrypted_path = "test_decrypted.txt";
    let data = b"hello file encryption";

    fs::write(input_path, data).unwrap();
    encrypt_file(input_path, encrypted_path, &key, &salt).unwrap();
    decrypt_file(encrypted_path, decrypted_path, &key).unwrap();

    let mut decrypted_data = Vec::new();
    fs::File::open(decrypted_path).unwrap().read_to_end(&mut decrypted_data).unwrap();

    assert_eq!(data, decrypted_data.as_slice());

    fs::remove_file(input_path).unwrap();
    fs::remove_file(encrypted_path).unwrap();
    fs::remove_file(decrypted_path).unwrap();
}