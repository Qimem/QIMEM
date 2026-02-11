// This file declares all the other files in `src/tests` as modules.

#[cfg(test)]
pub mod cipher_test;
#[cfg(test)]
pub mod file_encryption_test;
#[cfg(test)]
pub mod key_derivation_test;
#[cfg(test)]
pub mod signing_test;

#[cfg(test)]
use std::sync::Once;

#[cfg(test)]
static PYTHON_INIT: Once = Once::new();

#[cfg(test)]
pub fn init_python() {
    PYTHON_INIT.call_once(|| {
        pyo3::prepare_freethreaded_python();
    });
}

// Add a dummy test for the KeyStore to fix the final error
#[cfg(test)]
mod keystore_test {
    use crate::key_store::KeyStore;
    use crate::tests::init_python;
    use pyo3::Python;
    use std::fs;

    #[test]
    fn test_keystore_creation_and_persistence() {
        init_python();
        Python::with_gil(|py| {
            let path = "/tmp/qimem_test_keys.bin";
            // Ensure file is clean before test
            let _ = fs::remove_file(path);

            // 1. Create a new keystore and store a key
            let mut keystore = KeyStore::new(py, path, "very-strong-password").unwrap();
            let original_key = [42; 32];
            keystore
                .store_key(py, "my-test-key", &original_key)
                .unwrap();

            // 2. Create a new instance from the saved file
            let loaded_keystore = KeyStore::new(py, path, "very-strong-password").unwrap();
            let retrieved_key = loaded_keystore.retrieve_key(py, "my-test-key").unwrap();

            assert_eq!(Some(original_key.to_vec()), retrieved_key);

            // 3. Test that a wrong password fails
            assert!(KeyStore::new(py, path, "wrong-password").is_err());

            // Clean up the test file
            let _ = fs::remove_file(path);
        });
    }
}
