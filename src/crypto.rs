//! Cryptography primitives.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
#[cfg(feature = "chacha")]
use chacha20poly1305::ChaCha20Poly1305;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::envelope::Envelope;
use crate::error::{QimemError, Result};
use crate::keystore::KeyMaterial;

/// Symmetric algorithm identifier.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    #[cfg(feature = "chacha")]
    ChaCha20Poly1305,
}

impl Algorithm {
    pub(crate) fn id(self) -> u8 {
        match self {
            Self::Aes256Gcm => 1,
            #[cfg(feature = "chacha")]
            Self::ChaCha20Poly1305 => 2,
        }
    }

    pub(crate) fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Aes256Gcm),
            #[cfg(feature = "chacha")]
            2 => Ok(Self::ChaCha20Poly1305),
            _ => Err(QimemError::UnsupportedAlgorithm(id)),
        }
    }
}

/// Crypto engine.
#[derive(Debug, Clone)]
pub struct CryptoEngine {
    algorithm: Algorithm,
}

impl CryptoEngine {
    /// Creates a new engine.
    pub fn new(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }

    /// Encrypts plaintext into an envelope.
    pub fn encrypt(&self, key: &KeyMaterial, plaintext: &[u8]) -> Result<Envelope> {
        if !key.active {
            return Err(QimemError::KeyInactive(key.key_id));
        }
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let mut ciphertext_with_tag = match self.algorithm {
            Algorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key.material.as_slice())
                    .map_err(|_| QimemError::Encryption)?;
                cipher
                    .encrypt(Nonce::from_slice(&nonce), plaintext)
                    .map_err(|_| QimemError::Encryption)?
            }
            #[cfg(feature = "chacha")]
            Algorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key.material.as_slice())
                    .map_err(|_| QimemError::Encryption)?;
                cipher
                    .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), plaintext)
                    .map_err(|_| QimemError::Encryption)?
            }
        };

        let tag = ciphertext_with_tag.split_off(ciphertext_with_tag.len().saturating_sub(16));

        Ok(Envelope {
            version: 1,
            algorithm: self.algorithm,
            key_id: key.key_id,
            nonce: nonce.to_vec(),
            ciphertext: ciphertext_with_tag,
            tag,
        })
    }

    /// Decrypts an envelope.
    pub fn decrypt(&self, key: &KeyMaterial, envelope: &Envelope) -> Result<Vec<u8>> {
        if self.algorithm != envelope.algorithm {
            return Err(QimemError::InvalidEnvelope("algorithm mismatch"));
        }
        let mut combined = envelope.ciphertext.clone();
        combined.extend_from_slice(&envelope.tag);

        match envelope.algorithm {
            Algorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key.material.as_slice())
                    .map_err(|_| QimemError::Decryption)?;
                cipher
                    .decrypt(Nonce::from_slice(&envelope.nonce), combined.as_ref())
                    .map_err(|_| QimemError::Decryption)
            }
            #[cfg(feature = "chacha")]
            Algorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key.material.as_slice())
                    .map_err(|_| QimemError::Decryption)?;
                cipher
                    .decrypt(
                        chacha20poly1305::Nonce::from_slice(&envelope.nonce),
                        combined.as_ref(),
                    )
                    .map_err(|_| QimemError::Decryption)
            }
        }
    }
}
