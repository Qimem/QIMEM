#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use alloc::vec::Vec;
use hkdf::Hkdf;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

pub type SecretBytes = Zeroizing<Vec<u8>>;

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: SecretBytes,
}

#[derive(Clone, Debug)]
pub struct SharedSecret {
    pub bytes: SecretBytes,
}

#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub nonce: [u8; 12],
    pub body: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("invalid key material")]
    InvalidKey,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("signature failure")]
    Signature,
    #[error("pq failure")]
    PostQuantum,
}

pub trait KeyExchange {
    fn generate() -> KeyPair;
    fn derive_shared(private_key: &[u8], peer_public_key: &[u8]) -> Result<SharedSecret, CryptoError>;
}

pub trait Encryptor {
    fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Ciphertext, CryptoError>;
    fn decrypt(key: &[u8], ciphertext: &Ciphertext) -> Result<SecretBytes, CryptoError>;
}

pub trait Signer {
    fn sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

pub struct X25519Exchange;

impl KeyExchange for X25519Exchange {
    fn generate() -> KeyPair {
        let secret = x25519_dalek::StaticSecret::random();
        let public = x25519_dalek::PublicKey::from(&secret);
        KeyPair {
            public_key: public.as_bytes().to_vec(),
            private_key: Zeroizing::new(secret.to_bytes().to_vec()),
        }
    }

    fn derive_shared(private_key: &[u8], peer_public_key: &[u8]) -> Result<SharedSecret, CryptoError> {
        let private_bytes: [u8; 32] = private_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let public_bytes: [u8; 32] = peer_public_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let secret = x25519_dalek::StaticSecret::from(private_bytes);
        let public = x25519_dalek::PublicKey::from(public_bytes);
        let shared = secret.diffie_hellman(&public);
        Ok(SharedSecret {
            bytes: Zeroizing::new(shared.as_bytes().to_vec()),
        })
    }
}

pub struct Aes256GcmEncryptor;

impl Encryptor for Aes256GcmEncryptor {
    fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Ciphertext, CryptoError> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| CryptoError::Encrypt)?;
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let body = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).map_err(|_| CryptoError::Encrypt)?;
        Ok(Ciphertext { nonce, body })
    }

    fn decrypt(key: &[u8], ciphertext: &Ciphertext) -> Result<SecretBytes, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&ciphertext.nonce), ciphertext.body.as_ref())
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(Zeroizing::new(plaintext))
    }
}

pub struct Ed25519Signer;

impl Signer for Ed25519Signer {
    fn sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            &private_key.try_into().map_err(|_| CryptoError::InvalidKey)?,
        );
        use ed25519_dalek::Signer;
        Ok(signing_key.sign(message).to_bytes().to_vec())
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            &public_key.try_into().map_err(|_| CryptoError::InvalidKey)?,
        )
        .map_err(|_| CryptoError::Signature)?;
        let signature = ed25519_dalek::Signature::from_slice(signature).map_err(|_| CryptoError::Signature)?;
        use ed25519_dalek::Verifier;
        verifying_key.verify(message, &signature).map_err(|_| CryptoError::Signature)
    }
}

pub fn kyber_keypair() -> KeyPair {
    let (pk, sk) = kyber1024::keypair();
    KeyPair {
        public_key: pk.as_bytes().to_vec(),
        private_key: Zeroizing::new(sk.as_bytes().to_vec()),
    }
}

pub fn kyber_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, SharedSecret), CryptoError> {
    let pk = kyber1024::PublicKey::from_bytes(public_key).map_err(|_| CryptoError::PostQuantum)?;
    let (ct, ss) = kyber1024::encapsulate(&pk);
    Ok((
        ct.as_bytes().to_vec(),
        SharedSecret {
            bytes: Zeroizing::new(ss.as_bytes().to_vec()),
        },
    ))
}

pub fn hkdf_sha256(input: &[u8], info: &[u8]) -> SecretBytes {
    let hkdf = Hkdf::<Sha256>::new(None, input);
    let mut output = vec![0u8; 32];
    hkdf.expand(info, &mut output)
        .expect("32-byte HKDF expansion should not fail");
    Zeroizing::new(output)
}

pub fn hkdf_sha256_contextual(
    x25519_shared: &[u8],
    kyber_shared: &[u8],
    context: &[u8],
) -> SecretBytes {
    let mut hasher = Sha256::new();
    hasher.update(b"qimem-hybrid-salt-v1");
    hasher.update(context);
    let salt = hasher.finalize();

    let mut ikm = Vec::with_capacity(2 + x25519_shared.len() + 2 + kyber_shared.len());
    ikm.extend_from_slice(&(x25519_shared.len() as u16).to_be_bytes());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(&(kyber_shared.len() as u16).to_be_bytes());
    ikm.extend_from_slice(kyber_shared);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut output = vec![0u8; 32];
    hkdf.expand(b"qimem-hybrid-session-v1", &mut output)
        .expect("32-byte HKDF expansion should not fail");
    Zeroizing::new(output)
}

pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}
