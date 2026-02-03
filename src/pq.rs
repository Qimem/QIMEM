use pqcrypto_kyber::kyber1024;

pub fn kyber_keypair() -> (Vec<u8>, Vec<u8>) {
    let (public_key, secret_key) = kyber1024::keypair();
    (public_key.as_bytes().to_vec(), secret_key.as_bytes().to_vec())
}

pub fn kyber_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let public_key = kyber1024::PublicKey::from_bytes(public_key)
        .map_err(|_| "Invalid public key")?;
    let (ciphertext, shared_secret) = kyber1024::encapsulate(&public_key);
    Ok((ciphertext.as_bytes().to_vec(), shared_secret.as_bytes().to_vec()))
}

pub fn kyber_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let secret_key = kyber1024::SecretKey::from_bytes(secret_key)
        .map_err(|_| "Invalid secret key")?;
    let ciphertext = kyber1024::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| "Invalid ciphertext")?;
    let shared_secret = kyber1024::decapsulate(&ciphertext, &secret_key);
    Ok(shared_secret.as_bytes().to_vec())
}
