use crate::signing::{generate_keypair, sign_message, verify_signature};

#[test]
fn test_sign_verify() {
    let (public_key, secret_key) = generate_keypair().expect("Key generation failed");
    let message = b"Test message";
    let signature_vec = sign_message(&secret_key, message).expect("Signing failed");
    
    let signature: [u8; 64] = signature_vec.try_into().expect("Invalid signature length");

    let result = verify_signature(&public_key, message, &signature)
        .expect("Verification failed");
        
    assert!(result, "Signature verification failed");
}