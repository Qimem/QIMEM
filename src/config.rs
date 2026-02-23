//! Runtime configuration.

use std::net::SocketAddr;

use serde::Deserialize;

use crate::error::{QimemError, Result};

/// Engine mode.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// In-memory keys.
    Stateless,
    /// Postgres-backed keys.
    Stateful,
}

/// Application configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Runtime mode.
    pub mode: Mode,
    /// Database URL when stateful.
    pub database_url: Option<String>,
    /// Bind address.
    pub bind: SocketAddr,
}

impl Config {
    /// Load from environment.
    pub fn from_env() -> Result<Self> {
        let mode = std::env::var("QIMEM_MODE").unwrap_or_else(|_| "stateless".to_string());
        let mode = match mode.as_str() {
            "stateless" => Mode::Stateless,
            "stateful" => Mode::Stateful,
            _ => {
                return Err(QimemError::Config(
                    "QIMEM_MODE must be stateless|stateful".to_string(),
                ))
            }
        };

        let bind_raw = std::env::var("QIMEM_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let bind = bind_raw
            .parse::<SocketAddr>()
            .map_err(|err| QimemError::Config(format!("invalid QIMEM_BIND: {err}")))?;
        let database_url = std::env::var("DATABASE_URL").ok();
        if mode == Mode::Stateful && database_url.is_none() {
            return Err(QimemError::Config(
                "DATABASE_URL is required for stateful mode".to_string(),
            ));
        }
        Ok(Self {
            mode,
            database_url,
            bind,
        })
    }
}
