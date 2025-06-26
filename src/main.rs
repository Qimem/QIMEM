use std::io::{self, Write};
use base64::{Engine as _, engine::general_purpose};

// Import your existing Rust modules
mod q_keygen;
mod q_core;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- QIMEM CLI ---");

    print!("Enter a password to derive a key: ");
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    let password = password.trim();

    // Use your Rust q_keygen module directly
    let (key_bytes, salt_bytes) = q_keygen::derive_key_simple(password, None)?;
    
    // Display first 8 bytes of key and full salt in base64
    let key_preview = general_purpose::STANDARD.encode(&key_bytes[..8.min(key_bytes.len())]);
    let salt_b64 = general_purpose::STANDARD.encode(&salt_bytes);
    println!("\nDerived Key (first 8 bytes): {}", key_preview);
    println!("Generated Salt: {}", salt_b64);

    print!("\nEnter a message to encrypt: ");
    io::stdout().flush()?;
    let mut message = String::new();
    io::stdin().read_line(&mut message)?;
    let message_bytes = message.trim().as_bytes();

    println!("\nEncrypting...");
    let encrypted_bytes = q_core::encrypt_simple(message_bytes, &key_bytes)?;
    
    // Display first 16 bytes of encrypted data
    let encrypted_preview = general_purpose::STANDARD.encode(&encrypted_bytes[..16.min(encrypted_bytes.len())]);
    println!("Encrypted data (first 16 bytes): {}", encrypted_preview);

    println!("\nDecrypting...");
    let decrypted_bytes = q_core::decrypt_simple(&encrypted_bytes, &key_bytes)?;
    let decrypted_string = String::from_utf8(decrypted_bytes)?;
    
    println!("Decrypted message: {}", decrypted_string);

    if message.trim() == decrypted_string {
        println!("\nSuccess! Original message and decrypted message match.");
    } else {
        println!("\nError! Messages don't match.");
    }

    Ok(())
}