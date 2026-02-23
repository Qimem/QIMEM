#![deny(missing_docs)]
#![deny(unsafe_code)]

//! QIMEM deterministic encryption and key lifecycle engine.

pub mod api;
pub mod config;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod keystore;

pub use crypto::{Algorithm, CryptoEngine};
pub use envelope::Envelope;
pub use error::{QimemError, Result};
#[cfg(feature = "stateful")]
pub use keystore::PostgresKeyStore;
pub use keystore::{InMemoryKeyStore, KeyMaterial, KeyMetadata, KeyStore};
