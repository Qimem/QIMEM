use clap::{Parser, Subcommand};
use std::fs;
use qimem::cipher::{encrypt, decrypt};
use qimem::key_derivation::derive_key;
use hex;

#[derive(Parser)]
#[clap(name = "qimem")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        input: String,
        #[clap(long)]
        key: String,
    },
    Decrypt {
        input: String,
        #[clap(long)]
        key: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encrypt { input, key } => {
            let derived_key = derive_key(&key, "AxumObelisk2025አክሱም").unwrap();
            if fs::metadata(&input).is_ok() { // File input
                let data = fs::read(&input).unwrap();
                let ciphertext = encrypt(&data, &derived_key).unwrap();
                let output = format!("{}_encrypted.txt", input);
                fs::write(&output, ciphertext).unwrap();
                println!("Encrypted file saved to {}", output);
            } else { // Text input
                let ciphertext = encrypt(input.as_bytes(), &derived_key).unwrap();
                println!("{}", hex::encode(ciphertext));
            }
        }
        Commands::Decrypt { input, key } => {
            let derived_key = derive_key(&key, "AxumObelisk2025አክሱም").unwrap();
            if fs::metadata(&input).is_ok() {
                let data = fs::read(&input).unwrap();
                let plaintext = decrypt(&data, &derived_key).unwrap();
                let output = format!("{}_decrypted.txt", input);
                fs::write(&output, plaintext).unwrap();
                println!("Decrypted file saved to {}", output);
            } else {
                let ciphertext = hex::decode(&input).unwrap();
                let plaintext = decrypt(&ciphertext, &derived_key).unwrap();
                println!("{}", String::from_utf8(plaintext).unwrap());
            }
        }
    }
}