use qimem::q_core::{encrypt, decrypt};
use qimem::q_keygen::derive_key;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (key, _salt) = derive_key("password", None)?;
    let data = b"Sensitive data";
    let encrypted = encrypt(data, &key)?;
    let decrypted = decrypt(&encrypted, &key)?;
    assert_eq!(data, &decrypted[..]);
    println!("Encryption and decryption successful!");
    Ok(())
}