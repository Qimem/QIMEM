#[cfg(test)]
mod tests {
    // Corrected import: Assumes your functions are in a 'signing' module
    // at the crate root.
    use crate::signing::{generate_keypair, sign_message, verify_signature};

    // Or, if the functions are directly in your lib.rs or main.rs:
    // use crate::{generate_keypair, sign_message, verify_signature};

    #[test]
    fn test_sign_verify() {
        let (public_key, secret_key) = generate_keypair().expect("Key generation failed");
        let message = b"Test message";
        let signature = sign_message(&secret_key, message).expect("Signing failed");
        let is_valid = verify_signature(
            &public_key,
            message,
            &signature.try_into().expect("Invalid signature length"),
        )
        .expect("Verification failed");
        assert!(is_valid, "Signature verification failed");
    }
}