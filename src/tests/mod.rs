// This file declares all the other files in `src/tests` as modules.

#[cfg(test)]
pub mod cipher_test;
#[cfg(test)]
pub mod file_encryption_test;
#[cfg(test)]
pub mod key_derivation_test;
#[cfg(test)]
pub mod signing_test;

// Add a dummy test for the KeyStore to fix the final error
#[cfg(test)]
mod keystore_test {
    use crate::key_store::KeyStore;
    use std::fs;

    #[test]
    fn test_keystore_creation_and_persistence() {
        let path = "/tmp/qimem_test_keys.bin";
        // Ensure file is clean before test
        let _ = fs::remove_file(path); 

        // 1. Create a new keystore and store a key
        let mut keystore = KeyStore::new(path, "very-strong-password").unwrap();
        let original_key = [42; 32];
        keystore.store_key("my-test-key", original_key).unwrap();

        // 2. Create a new instance from the saved file
        let loaded_keystore = KeyStore::new(path, "very-strong-password").unwrap();
        let retrieved_key = loaded_keystore.retrieve_key("my-test-key").unwrap();
        
        assert_eq!(original_key, retrieved_key);

        // 3. Test that a wrong password fails
        assert!(KeyStore::new(path, "wrong-password").is_err());

        // Clean up the test file
        let _ = fs::remove_file(path);
    }
}