use crate::q_keygen::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_salt() {
        let (key1, salt1) = derive_key("password", None).expect("Key derivation failed");
        let (key2, salt2) = derive_key("password", None).expect("Key derivation failed");
        assert_ne!(salt1, salt2, "Random salts should differ");
        assert_ne!(key1, key2, "Keys should differ with different salts");
    }

    #[test]
    fn test_user_salt() {
        let (key1, salt1) = derive_key("password", Some("mysalt2025")).expect("Key derivation failed");
        let (key2, salt2) = derive_key("password", Some("mysalt2025")).expect("Key derivation failed");
        assert_eq!(salt1, salt2, "User salts should match");
        assert_eq!(key1, key2, "Keys should match with same salt");
    }

    #[test]
    fn test_invalid_salt() {
        let result = derive_key("password", Some("short"));
        assert!(result.is_err(), "Short salt should fail");
    }
}