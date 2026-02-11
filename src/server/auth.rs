use axum::extract::FromRef;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::{async_trait, extract::FromRequestParts};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use thiserror::Error;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub auth_disabled: bool,
}

impl AuthConfig {
    pub fn from_env() -> Result<Self, AuthError> {
        let auth_disabled = env::var("QIMEM_AUTH_DISABLED")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if auth_disabled {
            return Ok(Self {
                jwt_secret: String::new(),
                issuer: None,
                audience: None,
                auth_disabled,
            });
        }
        let jwt_secret = env::var("QIMEM_AUTH_JWT_SECRET")
            .map_err(|_| AuthError::MissingConfig("QIMEM_AUTH_JWT_SECRET"))?;
        let issuer = env::var("QIMEM_AUTH_ISSUER").ok();
        let audience = env::var("QIMEM_AUTH_AUDIENCE").ok();
        Ok(Self {
            jwt_secret,
            issuer,
            audience,
            auth_disabled,
        })
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing auth config: {0}")]
    MissingConfig(&'static str),
    #[error("missing authorization header")]
    MissingAuthorization,
    #[error("invalid authorization scheme")]
    InvalidScheme,
    #[error("invalid token")]
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let message = self.to_string();
        (StatusCode::UNAUTHORIZED, message).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iss: Option<String>,
    aud: Option<String>,
    tenant_id: Option<String>,
    scopes: Option<Vec<String>>,
    scope: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub subject: String,
    pub tenant_id: Option<String>,
    pub scopes: Vec<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    AuthConfig: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_config = AuthConfig::from_ref(state);
        if auth_config.auth_disabled {
            return Ok(AuthUser {
                subject: "anonymous".to_string(),
                tenant_id: None,
                scopes: Vec::new(),
            });
        }
        let header_value = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingAuthorization)?
            .to_str()
            .map_err(|_| AuthError::InvalidScheme)?;

        let token = header_value
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidScheme)?;

        let mut validation = Validation::new(Algorithm::HS256);
        if let Some(issuer) = &auth_config.issuer {
            validation.set_issuer(&[issuer]);
        }
        if let Some(audience) = &auth_config.audience {
            validation.set_audience(&[audience]);
        }

        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(auth_config.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AuthError::InvalidToken)?;

        let mut scopes = decoded.claims.scopes.unwrap_or_default();
        if scopes.is_empty() {
            if let Some(scope) = decoded.claims.scope {
                scopes = scope
                    .split_whitespace()
                    .filter(|value| !value.is_empty())
                    .map(|value| value.to_string())
                    .collect();
            }
        }

        if decoded.claims.tenant_id.is_none() {
            return Err(AuthError::InvalidToken);
        }

        Ok(AuthUser {
            subject: decoded.claims.sub,
            tenant_id: decoded.claims.tenant_id,
            scopes,
        })
    }
}
