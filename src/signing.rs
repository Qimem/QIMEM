use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Key generation failed")]
    KeyGenFailed,
    #[error("Signing failed")]
    SignFailed,
    #[error("Verification failed")]
    VerifyFailed,
}

pub fn generate_keypair() -> Result<([u8; 32], [u8; 32]), SigningError> {
    let rng = SystemRandom::new();
    
    // 1. Create a random 32-byte seed. This is the most fundamental form of the secret key.
    let mut seed = [0u8; 32];
    rng.fill(&mut seed).map_err(|_| SigningError::KeyGenFailed)?;

    // 2. Create a key pair directly from the seed.
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|_| SigningError::KeyGenFailed)?;
    
    // 3. Derive the public key from the same key pair.
    let public_key: [u8; 32] = key_pair.public_key().as_ref()
        .try_into()
        .map_err(|_| SigningError::KeyGenFailed)?;

    // 4. Return the public key and the seed. The seed now serves as our secret_key.
    // This guarantees the public key and secret key are a matched pair.
    Ok((public_key, seed))
}

pub fn sign_message(secret_key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, SigningError> {
    // Recreate the key pair from the secret key (which is the seed).
    let key_pair = Ed25519KeyPair::from_seed_unchecked(secret_key)
        .map_err(|_| SigningError::SignFailed)?;
    
    // Sign the message.
    let signature = key_pair.sign(message);
    
    Ok(signature.as_ref().to_vec())
}

pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<bool, SigningError> {
    let peer_public_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key);
    
    peer_public_key.verify(message, signature)
        .map(|_| true)
        .map_err(|_| SigningError::VerifyFailed)
}