//! Error types.

use thiserror::Error;

/// Result alias used by QIMEM.
pub type Result<T> = std::result::Result<T, QimemError>;

/// Top-level QIMEM error.
#[derive(Debug, Error)]
pub enum QimemError {
    /// Envelope version is unknown.
    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(u8),
    /// Envelope algorithm is unknown.
    #[error("unsupported algorithm id: {0}")]
    UnsupportedAlgorithm(u8),
    /// Envelope failed to parse.
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(&'static str),
    /// Key cannot be found.
    #[error("key not found: {0}")]
    KeyNotFound(uuid::Uuid),
    /// Key is inactive.
    #[error("key is inactive: {0}")]
    KeyInactive(uuid::Uuid),
    /// Encryption failed.
    #[error("encryption failed")]
    Encryption,
    /// Decryption failed.
    #[error("decryption failed")]
    Decryption,
    /// Serialization failure.
    #[error("serialization failed: {0}")]
    Serialization(String),
    /// Configuration failure.
    #[error("configuration failed: {0}")]
    Config(String),
    /// Stateful storage failure.
    #[cfg(feature = "stateful")]
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}
