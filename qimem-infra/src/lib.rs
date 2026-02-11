use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum InfraError {
    #[error("provider failure")]
    Provider,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayRequest {
    pub tenant_id: String,
    pub provider: String,
    pub encrypted_payload_b64: String,
    pub wrapped_dek_b64: String,
    pub key_version: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayResponse {
    pub provider: String,
    pub output: serde_json::Value,
}

pub trait AIProvider {
    fn forward(&self, request: &serde_json::Value) -> Result<serde_json::Value, InfraError>;
}

pub struct MockProvider;

impl AIProvider for MockProvider {
    fn forward(&self, request: &serde_json::Value) -> Result<serde_json::Value, InfraError> {
        let input = request.get("prompt").and_then(|p| p.as_str()).unwrap_or_default();
        let mut chars: Vec<char> = input.chars().collect();
        chars.reverse();
        Ok(serde_json::json!({"response": chars.into_iter().collect::<String>()}))
    }
}

pub fn zeroize_plaintext(buffer: &mut [u8]) {
    buffer.zeroize();
}
