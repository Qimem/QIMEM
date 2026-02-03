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
}

impl AuthConfig {
    pub fn from_env() -> Result<Self, AuthError> {
        let jwt_secret = env::var("BETTER_AUTH_JWT_SECRET")
            .map_err(|_| AuthError::MissingConfig("BETTER_AUTH_JWT_SECRET"))?;
        let issuer = env::var("BETTER_AUTH_ISSUER").ok();
        let audience = env::var("BETTER_AUTH_AUDIENCE").ok();
        Ok(Self {
            jwt_secret,
            issuer,
            audience,
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
    scope: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub subject: String,
    pub scope: Option<String>,
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

        Ok(AuthUser {
            subject: decoded.claims.sub,
            scope: decoded.claims.scope,
        })
    }
}
