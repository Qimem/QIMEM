use clap::{Parser, Subcommand};
use std::fs;
use qimem::q_core::{encrypt, decrypt};
use qimem::q_keygen::derive_key;
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
        #[clap(long)]
        salt: Option<String>,
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
        Commands::Encrypt { input, key, salt } => {
            let (derived_key, salt_bytes) = derive_key(&key, salt.as_deref()).unwrap();
            if fs::metadata(&input).is_ok() {
                let data = fs::read(&input).unwrap();
                let ciphertext = encrypt(&data, &derived_key, &salt_bytes).unwrap();
                let output = format!("{}_encrypted.txt", input);
                fs::write(&output, ciphertext).unwrap();
                println!("Encrypted file saved to {}", output);
            } else {
                let ciphertext = encrypt(input.as_bytes(), &derived_key, &salt_bytes).unwrap();
                println!("{}", hex::encode(ciphertext));
            }
        }
        Commands::Decrypt { input, key } => {
            let (derived_key, _) = derive_key(&key, None).unwrap();
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