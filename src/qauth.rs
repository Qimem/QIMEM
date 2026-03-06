//! QAuth identity and token service primitives.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{QimemError, Result};

/// Role to permissions mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role name.
    pub name: String,
    /// Permissions attached to the role.
    pub permissions: Vec<String>,
}

/// Realm/tenant configuration for QAuth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    /// Unique realm id.
    pub id: String,
    /// Display name.
    pub name: String,
}

/// Persisted user identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique user id.
    pub id: Uuid,
    /// Realm id.
    pub realm_id: String,
    /// Username/login.
    pub username: String,
    /// Password hash.
    pub password_hash: String,
    /// Assigned role names.
    pub roles: Vec<String>,
    /// Optional TOTP secret.
    pub totp_secret: Option<String>,
}

/// Registered OAuth client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    /// Client id.
    pub client_id: String,
    /// Client secret.
    pub client_secret: String,
    /// Realm id.
    pub realm_id: String,
    /// Redirect URI allowlist.
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    realm: String,
    roles: Vec<String>,
    permissions: Vec<String>,
    jti: String,
    token_use: String,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Clone)]
struct SigningKey {
    kid: String,
    secret: Vec<u8>,
}

/// Token response for OAuth-like flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// Access token JWT.
    pub access_token: String,
    /// Refresh token JWT.
    pub refresh_token: String,
    /// Seconds until expiration.
    pub expires_in: u64,
    /// Token type.
    pub token_type: String,
}

/// In-memory QAuth service with key rotation + revocation.
#[derive(Debug, Default, Clone)]
pub struct QAuthService {
    realms: Arc<RwLock<HashMap<String, Realm>>>,
    users: Arc<RwLock<HashMap<String, User>>>,
    clients: Arc<RwLock<HashMap<String, Client>>>,
    roles: Arc<RwLock<HashMap<String, HashMap<String, Role>>>>,
    revoked_jti: Arc<RwLock<HashSet<String>>>,
    signing_keys: Arc<RwLock<Vec<SigningKey>>>,
}

impl QAuthService {
    /// Create service with default signing key.
    pub fn new() -> Self {
        let default = SigningKey {
            kid: Uuid::new_v4().to_string(),
            secret: Uuid::new_v4().as_bytes().to_vec(),
        };
        Self {
            signing_keys: Arc::new(RwLock::new(vec![default])),
            ..Default::default()
        }
    }

    /// Create realm.
    pub fn create_realm(&self, id: &str, name: &str) -> Result<Realm> {
        let realm = Realm {
            id: id.to_string(),
            name: name.to_string(),
        };
        self.realms
            .write()
            .map_err(|_| QimemError::Config("realm lock poisoned".into()))?
            .insert(id.to_string(), realm.clone());
        Ok(realm)
    }

    /// Create role under realm.
    pub fn create_role(
        &self,
        realm_id: &str,
        name: &str,
        permissions: Vec<String>,
    ) -> Result<Role> {
        let role = Role {
            name: name.to_string(),
            permissions,
        };
        let mut roles = self
            .roles
            .write()
            .map_err(|_| QimemError::Config("role lock poisoned".into()))?;
        roles
            .entry(realm_id.to_string())
            .or_default()
            .insert(name.to_string(), role.clone());
        Ok(role)
    }

    /// Create OAuth client.
    pub fn create_client(&self, realm_id: &str, redirect_uris: Vec<String>) -> Result<Client> {
        let client = Client {
            client_id: Uuid::new_v4().to_string(),
            client_secret: Uuid::new_v4().to_string(),
            realm_id: realm_id.to_string(),
            redirect_uris,
        };
        self.clients
            .write()
            .map_err(|_| QimemError::Config("client lock poisoned".into()))?
            .insert(client.client_id.clone(), client.clone());
        Ok(client)
    }

    /// Register user with password.
    pub fn create_user(
        &self,
        realm_id: &str,
        username: &str,
        password: &str,
        roles: Vec<String>,
    ) -> Result<User> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| QimemError::Config("password hash failed".into()))?
            .to_string();

        let user = User {
            id: Uuid::new_v4(),
            realm_id: realm_id.to_string(),
            username: username.to_string(),
            password_hash: hash,
            roles,
            totp_secret: None,
        };
        self.users
            .write()
            .map_err(|_| QimemError::Config("user lock poisoned".into()))?
            .insert(format!("{}:{}", realm_id, username), user.clone());
        Ok(user)
    }

    /// Enable a static TOTP secret for a user.
    pub fn set_totp_secret(&self, realm_id: &str, username: &str, secret: String) -> Result<()> {
        let key = format!("{}:{}", realm_id, username);
        let mut users = self
            .users
            .write()
            .map_err(|_| QimemError::Config("user lock poisoned".into()))?;
        let user = users
            .get_mut(&key)
            .ok_or(QimemError::KeyNotFound(Uuid::nil()))?;
        user.totp_secret = Some(secret);
        Ok(())
    }

    /// Password grant equivalent; validates password and optional TOTP code.
    pub fn login(
        &self,
        client_id: &str,
        client_secret: &str,
        realm_id: &str,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<TokenPair> {
        let client = self
            .clients
            .read()
            .map_err(|_| QimemError::Config("client lock poisoned".into()))?
            .get(client_id)
            .cloned()
            .ok_or(QimemError::KeyNotFound(Uuid::nil()))?;
        if client.client_secret != client_secret || client.realm_id != realm_id {
            return Err(QimemError::Config("invalid client credentials".into()));
        }

        let user = self
            .users
            .read()
            .map_err(|_| QimemError::Config("user lock poisoned".into()))?
            .get(&format!("{}:{}", realm_id, username))
            .cloned()
            .ok_or(QimemError::KeyNotFound(Uuid::nil()))?;

        let parsed = PasswordHash::new(&user.password_hash)
            .map_err(|_| QimemError::Config("invalid password hash".into()))?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| QimemError::Config("invalid credentials".into()))?;

        if let Some(secret) = user.totp_secret.as_deref() {
            let code = totp_code.ok_or_else(|| QimemError::Config("mfa required".into()))?;
            let totp = totp_rs::TOTP::new_unchecked(
                totp_rs::Algorithm::SHA1,
                6,
                1,
                30,
                secret.as_bytes().to_vec(),
                Some("QAuth".to_string()),
                username.to_string(),
            );
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| QimemError::Config("time error".into()))?
                .as_secs();
            let valid = totp.check(code, now);
            if !valid {
                return Err(QimemError::Config("invalid mfa code".into()));
            }
        }

        let permissions = self.permissions_for_roles(realm_id, &user.roles)?;
        self.issue_token_pair(
            user.id.to_string(),
            realm_id.to_string(),
            user.roles,
            permissions,
        )
    }

    /// Refresh access token from refresh token.
    pub fn refresh(&self, refresh_token: &str) -> Result<TokenPair> {
        let claims = self.validate_token(refresh_token, "refresh")?;
        let permissions = self.permissions_for_roles(&claims.realm, &claims.roles)?;
        self.issue_token_pair(claims.sub, claims.realm, claims.roles, permissions)
    }

    /// Revoke token by JTI.
    pub fn revoke(&self, token: &str) -> Result<()> {
        let claims = self.validate_token(token, "access")?;
        self.revoked_jti
            .write()
            .map_err(|_| QimemError::Config("revoke lock poisoned".into()))?
            .insert(claims.jti);
        Ok(())
    }

    /// Validate access token and return claims payload.
    pub fn introspect_access(&self, token: &str) -> Result<serde_json::Value> {
        let claims = self.validate_token(token, "access")?;
        Ok(serde_json::json!({
            "active": true,
            "sub": claims.sub,
            "realm": claims.realm,
            "roles": claims.roles,
            "permissions": claims.permissions,
            "exp": claims.exp,
            "iat": claims.iat,
            "jti": claims.jti
        }))
    }

    /// Rotate JWT signing key.
    pub fn rotate_signing_key(&self) -> Result<String> {
        let mut keys = self
            .signing_keys
            .write()
            .map_err(|_| QimemError::Config("signing lock poisoned".into()))?;
        let kid = Uuid::new_v4().to_string();
        keys.push(SigningKey {
            kid: kid.clone(),
            secret: Uuid::new_v4().as_bytes().to_vec(),
        });
        Ok(kid)
    }

    fn permissions_for_roles(&self, realm_id: &str, role_names: &[String]) -> Result<Vec<String>> {
        let map = self
            .roles
            .read()
            .map_err(|_| QimemError::Config("role lock poisoned".into()))?;
        let mut permissions = HashSet::new();
        if let Some(realm_roles) = map.get(realm_id) {
            for role in role_names {
                if let Some(def) = realm_roles.get(role) {
                    for p in &def.permissions {
                        permissions.insert(p.clone());
                    }
                }
            }
        }
        Ok(permissions.into_iter().collect())
    }

    fn issue_token_pair(
        &self,
        sub: String,
        realm: String,
        roles: Vec<String>,
        permissions: Vec<String>,
    ) -> Result<TokenPair> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| QimemError::Config("time error".into()))?
            .as_secs() as usize;
        let key = self
            .signing_keys
            .read()
            .map_err(|_| QimemError::Config("signing lock poisoned".into()))?
            .last()
            .cloned()
            .ok_or_else(|| QimemError::Config("missing signing key".into()))?;

        let access_claims = Claims {
            sub: sub.clone(),
            realm: realm.clone(),
            roles: roles.clone(),
            permissions: permissions.clone(),
            jti: Uuid::new_v4().to_string(),
            token_use: "access".to_string(),
            exp: now + 900,
            iat: now,
        };
        let refresh_claims = Claims {
            sub,
            realm,
            roles,
            permissions,
            jti: Uuid::new_v4().to_string(),
            token_use: "refresh".to_string(),
            exp: now + 86_400,
            iat: now,
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(key.kid);
        let encoding = EncodingKey::from_secret(&key.secret);
        let access_token = encode(&header, &access_claims, &encoding)
            .map_err(|_| QimemError::Config("access token issuance failed".into()))?;
        let refresh_token = encode(&header, &refresh_claims, &encoding)
            .map_err(|_| QimemError::Config("refresh token issuance failed".into()))?;
        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: 900,
            token_type: "Bearer".to_string(),
        })
    }

    fn validate_token(&self, token: &str, expected_use: &str) -> Result<Claims> {
        let keys = self
            .signing_keys
            .read()
            .map_err(|_| QimemError::Config("signing lock poisoned".into()))?
            .clone();
        for key in keys.iter().rev() {
            let decoding = DecodingKey::from_secret(&key.secret);
            let validation = Validation::new(Algorithm::HS256);
            if let Ok(data) = decode::<Claims>(token, &decoding, &validation) {
                if data.claims.token_use != expected_use {
                    return Err(QimemError::Config("unexpected token use".into()));
                }
                if self
                    .revoked_jti
                    .read()
                    .map_err(|_| QimemError::Config("revoke lock poisoned".into()))?
                    .contains(&data.claims.jti)
                {
                    return Err(QimemError::Config("token revoked".into()));
                }
                return Ok(data.claims);
            }
        }
        Err(QimemError::Config("invalid token".into()))
    }
}
