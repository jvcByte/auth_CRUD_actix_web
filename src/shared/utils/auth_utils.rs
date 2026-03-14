//! Authentication helpers: password hashing, JWT creation/validation, and refresh token helpers.
//!
//! This module exposes a small set of utilities that the rest of the app uses:
//! - `AuthConfig` to load JWT / token lifetime config from environment
//! - `hash_password` / `verify_password` (Argon2id) for secure password storage
//! - `create_jwt` / `decode_jwt` for access token issuance and validation
//! - `generate_refresh_token` / `hash_refresh_token` / `verify_refresh_token_hash`
//!   for opaque refresh token lifecycle (rotate+store hashed on server)
use crate::shared::errors::api_errors::ApiError;
use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        rand_core::{OsRng, RngCore},
    },
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::OnceLock;
use uuid::Uuid;

/// JWT claims used in access tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub tv: i32,
}

/// Authentication configuration — loaded once at startup via `init()`.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub secret: String,
    pub access_exp_minutes: i64,
    pub refresh_exp_days: i64,
}

static AUTH_CONFIG: OnceLock<AuthConfig> = OnceLock::new();

impl AuthConfig {
    /// Call once at application startup (in `main`). Panics if required vars are missing.
    pub fn init() {
        let secret = env::var("JWT_SECRET").expect(".env: JWT_SECRET must be set");

        let access_exp_minutes = match env::var("JWT_EXP_MINUTES") {
            Ok(v) => v.parse::<i64>().unwrap_or_else(|_| {
                eprintln!("WARNING: Invalid JWT_EXP_MINUTES, defaulting to 15");
                15
            }),
            Err(_) => 15,
        };

        let refresh_exp_days = match env::var("REFRESH_TOKEN_EXP_DAYS") {
            Ok(v) => v.parse::<i64>().unwrap_or_else(|_| {
                eprintln!("WARNING: Invalid REFRESH_TOKEN_EXP_DAYS, defaulting to 30");
                30
            }),
            Err(_) => 30,
        };

        AUTH_CONFIG
            .set(AuthConfig {
                secret,
                access_exp_minutes,
                refresh_exp_days,
            })
            .expect("AuthConfig already initialized");
    }

    /// Get the global config. Panics if `init()` was not called first.
    pub fn get() -> &'static AuthConfig {
        AUTH_CONFIG
            .get()
            .expect("AuthConfig not initialized — call AuthConfig::init() at startup")
    }
}

/// Hash a plaintext password using Argon2id and return the encoded hash string.
///
/// The returned string includes parameters and salt in the PHC-password-hash format
/// so it can be stored directly in the DB and later verified via `verify_password`.
pub fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ApiError::InternalError("Password hashing failed".into()))?
        .to_string();
    Ok(password_hash)
}

/// Verify a plaintext password against the stored Argon2 password hash.
///
/// Returns `Ok(true)` if the password matches; `Ok(false)` if it doesn't match.
/// Any internal parsing / hashing error is mapped to `ApiError::InternalError`.
pub fn verify_password(hash: &str, password: &str) -> Result<bool, ApiError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|_| ApiError::InternalError("Invalid password hash".into()))?;
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Create a signed JWT access token for `user_id` including `token_version`.
///
/// Uses HS256 (HMAC SHA-256) with the `AuthConfig::secret`.
pub fn create_jwt(user_id: Uuid, token_version: i32, cfg: &AuthConfig) -> Result<String, ApiError> {
    let now = Utc::now();
    let exp = (now + Duration::minutes(cfg.access_exp_minutes)).timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        exp,
        tv: token_version,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(cfg.secret.as_ref()),
    )
    .map_err(|_| ApiError::InternalError("Token creation failed".into()))
}

/// Decode and validate a JWT access token using the configured secret.
///
/// Returns the parsed `TokenData<Claims>` on success or an `ApiError::BadRequest`
/// if the token is invalid or expired.
pub fn decode_jwt(token: &str, cfg: &AuthConfig) -> Result<TokenData<Claims>, ApiError> {
    let validation = Validation::default();
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(cfg.secret.as_ref()),
        &validation,
    )
    .map_err(|e| ApiError::BadRequest(format!("Invalid token: {}", e)))
}

/// Generate a new opaque refresh token (suitable to hand to a client).
///
/// Returns the plaintext token. The caller must hash & store it (see `hash_refresh_token`)
/// and associate it with a user and expiry in the database. The plaintext token is shown
/// only once at issuance to the client.
pub fn generate_refresh_token() -> String {
    // Use 64 bytes of secure randomness and hex-encode them to a compact ASCII token.
    let mut bytes = [0u8; 64];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    // hex encode (no extra deps)
    let mut out = String::with_capacity(128);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Hash a refresh token for safe storage using Argon2.
///
/// The returned string can be stored in DB and later compared with a presented
/// token via `verify_refresh_token_hash`.
pub fn hash_refresh_token(token: &str) -> Result<String, ApiError> {
    // Reuse Argon2 hashing for refresh tokens to avoid adding extra dependencies.
    hash_password(token)
}

/// Convenience: compute refresh token expiry timestamp (seconds since epoch)
pub fn refresh_expiry_timestamp(cfg: &AuthConfig) -> i64 {
    let now = Utc::now();
    (now + Duration::days(cfg.refresh_exp_days)).timestamp()
}
