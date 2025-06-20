use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, Signature, UnparsedPublicKey, ED25519};

pub fn generate_keypair() -> (Ed25519KeyPair, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8_document = Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("RNG failure");
    let pkcs8_bytes = pkcs8_document.as_ref().to_vec();
    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes)
        .expect("Invalid key");
    (keypair, pkcs8_bytes)
}

pub fn sign_message(keypair: &Ed25519KeyPair, message: &[u8]) -> Vec<u8> {
    let signature: Signature = keypair.sign(message);
    signature.as_ref().to_vec()
}

pub fn verify_signature(pub_key_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> bool {
    let pub_key = UnparsedPublicKey::new(&ED25519, pub_key_bytes);
    pub_key.verify(message, sig_bytes).is_ok()
}