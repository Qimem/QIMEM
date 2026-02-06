use hkdf::Hkdf;
use pqcrypto_kyber::kyber1024;
use rand::RngCore;
use sha2::Sha256;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Copy, Debug)]
pub enum PqAlgorithm {
    Kyber1024,
}

impl PqAlgorithm {
    pub fn from_name(name: Option<&str>) -> Result<Self, &'static str> {
        match name.unwrap_or("kyber1024").to_lowercase().as_str() {
            "kyber1024" => Ok(PqAlgorithm::Kyber1024),
            _ => Err("unsupported algorithm"),
        }
    }
}

impl std::fmt::Display for PqAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqAlgorithm::Kyber1024 => write!(f, "kyber1024"),
        }
    }
}

pub trait KexAlgorithm {
    fn keypair() -> (Vec<u8>, Vec<u8>);
    fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str>;
    fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str>;
    fn algorithm_id() -> &'static str;
}

pub struct Kyber1024Kex;

impl KexAlgorithm for Kyber1024Kex {
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = kyber1024::keypair();
        (public_key.as_bytes().to_vec(), secret_key.as_bytes().to_vec())
    }

    fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        let public_key = kyber1024::PublicKey::from_bytes(public_key)
            .map_err(|_| "Invalid public key")?;
        let (ciphertext, shared_secret) = kyber1024::encapsulate(&public_key);
        Ok((ciphertext.as_bytes().to_vec(), shared_secret.as_bytes().to_vec()))
    }

    fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let secret_key = kyber1024::SecretKey::from_bytes(secret_key)
            .map_err(|_| "Invalid secret key")?;
        let ciphertext = kyber1024::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| "Invalid ciphertext")?;
        let shared_secret = kyber1024::decapsulate(&ciphertext, &secret_key);
        Ok(shared_secret.as_bytes().to_vec())
    }

    fn algorithm_id() -> &'static str {
        "kyber1024"
    }
}

impl PqAlgorithm {
    pub fn algorithm_id(&self) -> &'static str {
        match self {
            PqAlgorithm::Kyber1024 => "kyber1024",
        }
    }
}

pub struct PqKeypair {
    pub algorithm: PqAlgorithm,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub fn keypair(algorithm: PqAlgorithm) -> PqKeypair {
    match algorithm {
        PqAlgorithm::Kyber1024 => {
            let (public_key, secret_key) = kyber1024::keypair();
            PqKeypair {
                algorithm,
                public_key: public_key.as_bytes().to_vec(),
                secret_key: secret_key.as_bytes().to_vec(),
            }
        }
    }
}

pub fn encapsulate(
    algorithm: PqAlgorithm,
    public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    match algorithm {
        PqAlgorithm::Kyber1024 => {
            let public_key = kyber1024::PublicKey::from_bytes(public_key)
                .map_err(|_| "Invalid public key")?;
            let (ciphertext, shared_secret) = kyber1024::encapsulate(&public_key);
            Ok((ciphertext.as_bytes().to_vec(), shared_secret.as_bytes().to_vec()))
        }
    }
}

pub fn decapsulate(
    algorithm: PqAlgorithm,
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    match algorithm {
        PqAlgorithm::Kyber1024 => {
            let secret_key = kyber1024::SecretKey::from_bytes(secret_key)
                .map_err(|_| "Invalid secret key")?;
            let ciphertext = kyber1024::Ciphertext::from_bytes(ciphertext)
                .map_err(|_| "Invalid ciphertext")?;
            let shared_secret = kyber1024::decapsulate(&ciphertext, &secret_key);
            Ok(shared_secret.as_bytes().to_vec())
        }
    }
}

pub fn hybrid_session(
    algorithm: PqAlgorithm,
    client_x25519_public: &[u8],
    client_kyber_public: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), &'static str> {
    let mut server_private = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut server_private);
    let server_secret = StaticSecret::from(server_private);
    let server_public = PublicKey::from(&server_secret);
    let client_public = PublicKey::from(
        <[u8; 32]>::try_from(client_x25519_public).map_err(|_| "Invalid X25519 key")?,
    );
    let x25519_shared = server_secret.diffie_hellman(&client_public);
    let (ciphertext, kyber_shared) = encapsulate(algorithm, client_kyber_public)?;
    let hk = Hkdf::<Sha256>::new(None, &[x25519_shared.as_bytes(), kyber_shared.as_slice()].concat());
    let mut session_key = vec![0u8; 32];
    hk.expand(b"qimem-hybrid-session", &mut session_key)
        .map_err(|_| "HKDF failed")?;
    Ok((
        server_public.as_bytes().to_vec(),
        session_key,
        ciphertext,
    ))
}
