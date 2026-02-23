use std::sync::Arc;

use base64::Engine;
use clap::{Parser, Subcommand};
use qimem::{Algorithm, CryptoEngine, Envelope, InMemoryKeyStore, KeyStore};
use serde_json::json;
use uuid::Uuid;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Keygen,
    Encrypt {
        #[arg(long)]
        key_id: Uuid,
        #[arg(long)]
        input: String,
    },
    Decrypt {
        #[arg(long)]
        input: String,
    },
    Rotate {
        #[arg(long)]
        key_id: Uuid,
    },
}

fn print_json(value: serde_json::Value) -> i32 {
    match serde_json::to_string(&value) {
        Ok(text) => {
            println!("{text}");
            0
        }
        Err(err) => {
            eprintln!("{{\"error\":\"{}\"}}", err);
            1
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::default());

    let code = match cli.command {
        Commands::Keygen => match store.create_key() {
            Ok(meta) => print_json(json!(meta)),
            Err(err) => print_json(json!({"error": err.to_string()})),
        },
        Commands::Encrypt { key_id, input } => {
            let result = (|| {
                let key = store.get_key(key_id)?;
                let envelope =
                    CryptoEngine::new(Algorithm::Aes256Gcm).encrypt(&key, input.as_bytes())?;
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(envelope.serialize_binary()?);
                Ok::<serde_json::Value, qimem::QimemError>(json!({"envelope": encoded}))
            })();
            match result {
                Ok(value) => print_json(value),
                Err(err) => print_json(json!({"error": err.to_string()})),
            }
        }
        Commands::Decrypt { input } => {
            let result = (|| {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(input)
                    .map_err(|_| qimem::QimemError::InvalidEnvelope("invalid base64"))?;
                let envelope = Envelope::deserialize_binary(&bytes)?;
                let key = store.get_key(envelope.key_id)?;
                let plaintext = CryptoEngine::new(envelope.algorithm).decrypt(&key, &envelope)?;
                let text =
                    String::from_utf8(plaintext).map_err(|_| qimem::QimemError::Decryption)?;
                Ok::<serde_json::Value, qimem::QimemError>(json!({"plaintext": text}))
            })();
            match result {
                Ok(value) => print_json(value),
                Err(err) => print_json(json!({"error": err.to_string()})),
            }
        }
        Commands::Rotate { key_id } => match store.rotate_key(key_id) {
            Ok(meta) => print_json(json!(meta)),
            Err(err) => print_json(json!({"error": err.to_string()})),
        },
    };

    std::process::exit(code);
}
