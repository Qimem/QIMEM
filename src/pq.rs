use hkdf::Hkdf;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
pub enum PqAlgorithm {
    Kyber1024,
}

pub type HybridSession = (Vec<u8>, Vec<u8>, Vec<u8>);

impl PqAlgorithm {
    pub fn from_name(name: Option<&str>) -> Result<Self, &'static str> {
        match name.unwrap_or("kyber1024").to_lowercase().as_str() {
            "kyber1024" => Ok(PqAlgorithm::Kyber1024),
            _ => Err("unsupported algorithm"),
        }
    }

    pub fn algorithm_id(&self) -> &'static str {
        match self {
            PqAlgorithm::Kyber1024 => "kyber1024",
        }
    }
}

impl std::fmt::Display for PqAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.algorithm_id())
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
        (
            public_key.as_bytes().to_vec(),
            secret_key.as_bytes().to_vec(),
        )
    }

    fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        encapsulate(PqAlgorithm::Kyber1024, public_key)
    }

    fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        decapsulate(PqAlgorithm::Kyber1024, secret_key, ciphertext)
    }

    fn algorithm_id() -> &'static str {
        "kyber1024"
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
            let public_key =
                kyber1024::PublicKey::from_bytes(public_key).map_err(|_| "Invalid public key")?;
            let (ciphertext, shared_secret) = kyber1024::encapsulate(&public_key);
            Ok((
                ciphertext.as_bytes().to_vec(),
                shared_secret.as_bytes().to_vec(),
            ))
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
            let secret_key =
                kyber1024::SecretKey::from_bytes(secret_key).map_err(|_| "Invalid secret key")?;
            let ciphertext =
                kyber1024::Ciphertext::from_bytes(ciphertext).map_err(|_| "Invalid ciphertext")?;
            let shared_secret = kyber1024::decapsulate(&ciphertext, &secret_key);
            Ok(shared_secret.as_bytes().to_vec())
        }
    }
}

fn derive_hybrid_session_key(
    x25519_shared: &[u8],
    kyber_shared: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, &'static str> {
    // Domain-separated composition per QIMEM-HYBRID-V1:
    // salt = SHA256("qimem-hybrid-salt-v1" || context)
    // ikm  = len(x25519)||x25519||len(kyber)||kyber
    let mut hasher = Sha256::new();
    hasher.update(b"qimem-hybrid-salt-v1");
    hasher.update(context);
    let salt = hasher.finalize();

    let mut ikm = Vec::with_capacity(2 + x25519_shared.len() + 2 + kyber_shared.len());
    ikm.extend_from_slice(&(x25519_shared.len() as u16).to_be_bytes());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(&(kyber_shared.len() as u16).to_be_bytes());
    ikm.extend_from_slice(kyber_shared);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut session_key = vec![0u8; 32];
    hk.expand(b"qimem-hybrid-session-v1", &mut session_key)
        .map_err(|_| "HKDF failed")?;
    Ok(session_key)
}

pub fn hybrid_session(
    algorithm: PqAlgorithm,
    client_x25519_public: &[u8],
    client_kyber_public: &[u8],
) -> Result<HybridSession, &'static str> {
    let server_secret = StaticSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret);
    let client_public = PublicKey::from(
        <[u8; 32]>::try_from(client_x25519_public).map_err(|_| "Invalid X25519 key")?,
    );

    let x25519_shared = server_secret.diffie_hellman(&client_public);
    let (ciphertext, kyber_shared) = encapsulate(algorithm, client_kyber_public)?;

    let mut context = Vec::with_capacity(64 + algorithm.algorithm_id().len());
    context.extend_from_slice(b"qimem-hybrid-context-v1");
    context.extend_from_slice(server_public.as_bytes());
    context.extend_from_slice(client_x25519_public);
    context.extend_from_slice(algorithm.algorithm_id().as_bytes());

    let x_shared = Zeroizing::new(x25519_shared.as_bytes().to_vec());
    let k_shared = Zeroizing::new(kyber_shared);
    let session_key = derive_hybrid_session_key(&x_shared, &k_shared, &context)?;

    Ok((server_public.as_bytes().to_vec(), session_key, ciphertext))
}

pub fn generate_x25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (public.as_bytes().to_vec(), secret.to_bytes().to_vec())
}
