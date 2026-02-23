//! Key storage abstractions.

mod memory;
#[cfg(feature = "stateful")]
mod postgres;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::Result;

pub use memory::InMemoryKeyStore;
#[cfg(feature = "stateful")]
pub use postgres::PostgresKeyStore;

/// Metadata for a key record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key identifier.
    pub key_id: Uuid,
    /// Lineage identifier.
    pub lineage_id: Uuid,
    /// Rotation version.
    pub version: i32,
    /// Whether key is active for encryption.
    pub active: bool,
}

/// Key material with metadata.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// Key identifier.
    pub key_id: Uuid,
    /// Encryption key bytes.
    pub material: Zeroizing<Vec<u8>>,
    /// Active status.
    pub active: bool,
}

/// Key store contract.
pub trait KeyStore: Send + Sync {
    /// Create a new root key.
    fn create_key(&self) -> Result<KeyMetadata>;
    /// Retrieve key material by key id.
    fn get_key(&self, key_id: Uuid) -> Result<KeyMaterial>;
    /// Rotate a key and return the new active version.
    fn rotate_key(&self, key_id: Uuid) -> Result<KeyMetadata>;
}

pub(crate) fn generate_key_material() -> Zeroizing<Vec<u8>> {
    let mut key = vec![0_u8; 32];
    OsRng.fill_bytes(&mut key);
    Zeroizing::new(key)
}
