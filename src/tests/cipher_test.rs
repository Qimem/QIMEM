use argon2::{Algorithm, Argon2, Params, Version, PasswordHasher};
use rand::{rngs::ThreadRng, RngCore};
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64;
use base64::Engine;
use argon2::password_hash::SaltString;

#[test]
fn test_key_derivation() {
    let password = "testpassword";
    let mut salt = [0u8; 16];
    ThreadRng::default().fill_bytes(&mut salt);

    let salt_b64 = BASE64.encode(&salt);
    let salt_ref = SaltString::from_b64(&salt_b64).unwrap();
    let params = Params::new(32768, 4, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2.hash_password(password.as_bytes(), &salt_ref).unwrap();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.hash.unwrap().as_bytes());
    
    assert_eq!(key.len(), 32, "Key length should be 32 bytes");
}