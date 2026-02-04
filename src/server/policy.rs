use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use std::env;
use thiserror::Error;

use crate::totp;

#[derive(Clone, Debug)]
pub struct PolicyConfig {
    pub allowed_countries: Option<Vec<String>>,
    pub require_mfa: bool,
    pub mfa_totp_secret: Option<String>,
}

impl PolicyConfig {
    pub fn from_env() -> Self {
        let allowed_countries = env::var("QIMEM_ALLOWED_COUNTRIES")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(|item| item.trim().to_uppercase())
                    .filter(|item| !item.is_empty())
                    .collect::<Vec<_>>()
            })
            .filter(|list| !list.is_empty());
        let require_mfa = env::var("QIMEM_REQUIRE_MFA")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let mfa_totp_secret = env::var("QIMEM_MFA_TOTP_SECRET").ok();
        Self {
            allowed_countries,
            require_mfa,
            mfa_totp_secret,
        }
    }

    pub fn enforce(&self, headers: &HeaderMap) -> Result<(), PolicyError> {
        if let Some(allowed) = &self.allowed_countries {
            let header_value = headers
                .get("x-vercel-ip-country")
                .or_else(|| headers.get("x-geo-country"))
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_uppercase())
                .ok_or(PolicyError::MissingGeo)?;
            if !allowed.contains(&header_value) {
                return Err(PolicyError::ForbiddenGeo);
            }
        }

        if self.require_mfa {
            let code = headers
                .get("x-qimem-totp")
                .and_then(|value| value.to_str().ok())
                .ok_or(PolicyError::MissingMfa)?;
            let secret = self
                .mfa_totp_secret
                .as_deref()
                .ok_or(PolicyError::MissingMfaSecret)?;
            let is_valid = totp::verify_totp_code(secret, code)
                .map_err(|_| PolicyError::InvalidMfa)?;
            if !is_valid {
                return Err(PolicyError::InvalidMfa);
            }
        }

        Ok(())
    }
}

pub async fn policy_middleware(
    State(policy): State<PolicyConfig>,
    request: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    match policy.enforce(request.headers()) {
        Ok(()) => next.run(request).await,
        Err(err) => (StatusCode::FORBIDDEN, err.to_string()).into_response(),
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("missing geofence header")]
    MissingGeo,
    #[error("request blocked by geofence policy")]
    ForbiddenGeo,
    #[error("missing MFA code")]
    MissingMfa,
    #[error("missing MFA secret")]
    MissingMfaSecret,
    #[error("invalid MFA code")]
    InvalidMfa,
}
