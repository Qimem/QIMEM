//! Envelope format and serialization.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::Algorithm;
use crate::error::{QimemError, Result};

/// Deterministic envelope format v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Envelope version.
    pub version: u8,
    /// Encryption algorithm.
    pub algorithm: Algorithm,
    /// Key identifier.
    pub key_id: Uuid,
    /// Nonce bytes.
    pub nonce: Vec<u8>,
    /// Ciphertext bytes without tag.
    pub ciphertext: Vec<u8>,
    /// Authentication tag.
    pub tag: Vec<u8>,
}

impl Envelope {
    /// Serializes to deterministic binary format.
    pub fn serialize_binary(&self) -> Result<Vec<u8>> {
        if self.version != 1 {
            return Err(QimemError::UnsupportedVersion(self.version));
        }
        let nonce_len = u16::try_from(self.nonce.len())
            .map_err(|_| QimemError::InvalidEnvelope("nonce too long"))?;
        let ct_len = u32::try_from(self.ciphertext.len())
            .map_err(|_| QimemError::InvalidEnvelope("ciphertext too long"))?;
        let tag_len = u8::try_from(self.tag.len())
            .map_err(|_| QimemError::InvalidEnvelope("tag too long"))?;

        let mut out = Vec::with_capacity(
            1 + 1 + 16 + 2 + self.nonce.len() + 4 + self.ciphertext.len() + 1 + self.tag.len(),
        );
        out.push(self.version);
        out.push(self.algorithm.id());
        out.extend_from_slice(self.key_id.as_bytes());
        out.extend_from_slice(&nonce_len.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&ct_len.to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.push(tag_len);
        out.extend_from_slice(&self.tag);
        Ok(out)
    }

    /// Deserializes from deterministic binary format.
    pub fn deserialize_binary(input: &[u8]) -> Result<Self> {
        let mut idx = 0_usize;
        let version = *input
            .get(idx)
            .ok_or(QimemError::InvalidEnvelope("missing version"))?;
        idx += 1;
        if version != 1 {
            return Err(QimemError::UnsupportedVersion(version));
        }
        let alg_id = *input
            .get(idx)
            .ok_or(QimemError::InvalidEnvelope("missing algorithm"))?;
        idx += 1;
        let algorithm = Algorithm::from_id(alg_id)?;

        let key_bytes = input
            .get(idx..idx + 16)
            .ok_or(QimemError::InvalidEnvelope("missing key id"))?;
        let key_id = Uuid::from_slice(key_bytes)
            .map_err(|_| QimemError::InvalidEnvelope("invalid key id"))?;
        idx += 16;

        let nonce_len_bytes = input
            .get(idx..idx + 2)
            .ok_or(QimemError::InvalidEnvelope("missing nonce length"))?;
        let nonce_len = u16::from_be_bytes([nonce_len_bytes[0], nonce_len_bytes[1]]) as usize;
        idx += 2;

        let nonce = input
            .get(idx..idx + nonce_len)
            .ok_or(QimemError::InvalidEnvelope("invalid nonce"))?
            .to_vec();
        idx += nonce_len;

        let ct_len_bytes = input
            .get(idx..idx + 4)
            .ok_or(QimemError::InvalidEnvelope("missing ciphertext length"))?;
        let ct_len = u32::from_be_bytes([
            ct_len_bytes[0],
            ct_len_bytes[1],
            ct_len_bytes[2],
            ct_len_bytes[3],
        ]) as usize;
        idx += 4;

        let ciphertext = input
            .get(idx..idx + ct_len)
            .ok_or(QimemError::InvalidEnvelope("invalid ciphertext"))?
            .to_vec();
        idx += ct_len;

        let tag_len = *input
            .get(idx)
            .ok_or(QimemError::InvalidEnvelope("missing tag length"))?
            as usize;
        idx += 1;

        let tag = input
            .get(idx..idx + tag_len)
            .ok_or(QimemError::InvalidEnvelope("invalid tag"))?
            .to_vec();
        idx += tag_len;

        if idx != input.len() {
            return Err(QimemError::InvalidEnvelope("trailing bytes"));
        }

        Ok(Self {
            version,
            algorithm,
            key_id,
            nonce,
            ciphertext,
            tag,
        })
    }

    /// Serializes to JSON bytes.
    pub fn serialize_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|err| QimemError::Serialization(err.to_string()))
    }

    /// Deserializes from JSON bytes.
    pub fn deserialize_json(input: &[u8]) -> Result<Self> {
        let envelope: Self = serde_json::from_slice(input)
            .map_err(|err| QimemError::Serialization(err.to_string()))?;
        if envelope.version != 1 {
            return Err(QimemError::UnsupportedVersion(envelope.version));
        }
        Ok(envelope)
    }
}
