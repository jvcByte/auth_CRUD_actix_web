use crate::api::auth::dto::{LoginRequest, RefreshRequest, RegisterRequest, TokenResponse};
use crate::api::refresh_tokens::repository::RefreshTokenRepository;
use crate::api::users::dto::{CreateUser, UserResponse};
use crate::api::users::repository::UserRepository;
use crate::api::users::service::UserService;
use crate::shared::errors::api_errors::ApiError;
use crate::shared::middleware::auth::AuthenticatedUser;
use crate::shared::utils::app_state::AppState;
use crate::shared::utils::auth_utils::{
    AuthConfig, create_jwt, generate_refresh_token, hash_refresh_token, refresh_expiry_timestamp,
    verify_password,
};
use actix_web::{HttpResponse, Result, web};
use chrono::{DateTime, Utc};
use sea_orm::prelude::DateTimeWithTimeZone;

/// Register a new user and return an access token, refresh token and user info.
///
/// Expected JSON:
/// {
///   "name": "...",
///   "email": "...",
///   "password": "..."
/// }
pub async fn register(
    body: web::Json<RegisterRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let req = body.into_inner();

    // Build the CreateUser DTO used by existing service logic.
    let create = CreateUser {
        name: req.name.clone(),
        email: req.email.clone(),
    };

    // Create the user (this hashes password and persists auth fields).
    let id = UserService::register_user(&state.db, create, req.password)
        .await
        .map_err(|e| e)?;

    // Fetch created user to include public user info in the response.
    let user_model = UserRepository::find_by_id(&state.db, id)
        .await
        .map_err(|err| ApiError::InternalError(format!("DB Error: {}", err)))?
        .ok_or_else(|| ApiError::InternalError("Created user not found".into()))?;

    let user = UserResponse {
        id: user_model.id,
        name: user_model.name,
        email: user_model.email,
    };

    // Create refresh token (opaque), hash it and store in DB with expiry
    let cfg = AuthConfig::get();
    let refresh_plain = generate_refresh_token();
    let refresh_hash = hash_refresh_token(&refresh_plain)?;
    let refresh_expires_at = Some(DateTimeWithTimeZone::from(
        DateTime::from_timestamp(refresh_expiry_timestamp(&cfg), 0)
            .ok_or_else(|| ApiError::InternalError("Failed to compute expiry".into()))?,
    ));

    let _ =
        RefreshTokenRepository::create(&state.db, user_model.id, refresh_hash, refresh_expires_at)
            .await
            .map_err(|_| ApiError::InternalError("Failed to store refresh token".into()))?;

    // Create access token
    let access_token = create_jwt(id, user_model.token_version, &cfg)?;
    let expires_in = cfg.access_exp_minutes * 60;

    Ok(HttpResponse::Created().json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        refresh_token: Some(refresh_plain),
        user: Some(user),
    }))
}

/// Login an existing user and return an access token and refresh token and user info.
///
/// Expected JSON:
/// {
///   "email": "...",
///   "password": "..."
/// }
pub async fn login(
    body: web::Json<LoginRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let req = body.into_inner();

    // Authenticate credentials and create access token (service returns token string).
    let access_token = UserService::login(&state.db, &req.email, &req.password)
        .await
        .map_err(|e| e)?;

    // Retrieve user public info
    let user_model = UserRepository::find_by_email(&state.db, &req.email)
        .await
        .map_err(|_| ApiError::InternalError("DB error".to_string()))?
        .ok_or_else(|| ApiError::NotFound("Invalid credentials".into()))?;

    let user = UserResponse {
        id: user_model.id,
        name: user_model.name,
        email: user_model.email,
    };

    // Compute expiry from config
    let cfg = AuthConfig::get();
    let expires_in = cfg.access_exp_minutes * 60;

    // Create and persist refresh token with expiry
    let refresh_plain = generate_refresh_token();
    let refresh_hash = hash_refresh_token(&refresh_plain)?;
    let refresh_expires_at = Some(DateTimeWithTimeZone::from(
        DateTime::from_timestamp(refresh_expiry_timestamp(&cfg), 0)
            .ok_or_else(|| ApiError::InternalError("Failed to compute expiry".into()))?,
    ));

    let _ =
        RefreshTokenRepository::create(&state.db, user_model.id, refresh_hash, refresh_expires_at)
            .await
            .map_err(|_| ApiError::InternalError("Failed to store refresh token".into()))?;

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        refresh_token: Some(refresh_plain),
        user: Some(user),
    }))
}

/// Refresh access token using a refresh token.
///
/// Full flow:
/// - Client presents refresh token.
/// - Server verifies it against stored hashes for the user.
/// - Verify it exists, is not revoked and not expired.
/// - Create new access token and rotate refresh token (issue a new one, store hash, revoke old).
pub async fn refresh(
    body: web::Json<RefreshRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let req = body.into_inner();

    // We need to find the matching token by verifying against all non-revoked tokens
    // This is necessary because Argon2 hashes include a salt and can't be looked up directly
    let all_tokens = RefreshTokenRepository::find_all_active(&state.db)
        .await
        .map_err(|_| ApiError::InternalError("DB error".to_string()))?;

    let mut matching_record = None;
    for token in all_tokens {
        if let Ok(true) = verify_password(&token.token_hash, &req.refresh_token) {
            matching_record = Some(token);
            break;
        }
    }

    let record =
        matching_record.ok_or_else(|| ApiError::NotFound("Invalid refresh token".into()))?;

    // Check revoked
    if record.revoked {
        return Err(ApiError::NotFound("Refresh token revoked".into()));
    }

    // Optionally check expiry if stored (skipped if None)
    // If expired, return NotFound/Unauthorized
    if let Some(exp) = record.expires_at {
        // Compare by unix timestamp to avoid timezone type inference issues
        let now_ts = Utc::now().timestamp();
        if exp.timestamp() < now_ts {
            return Err(ApiError::NotFound("Refresh token expired".into()));
        }
    }

    // Issue new access token with the user's current token version
    let cfg = AuthConfig::get();

    // Fetch user to get current token version
    let user = UserRepository::find_by_id(&state.db, record.user_id)
        .await
        .map_err(|_| ApiError::InternalError("DB error".to_string()))?
        .ok_or_else(|| ApiError::NotFound("User not found".into()))?;

    let access_token = create_jwt(record.user_id, user.token_version, &cfg)?;
    let expires_in = cfg.access_exp_minutes * 60;

    // Rotate refresh token: create a new one with expiry and revoke the old
    let new_plain = generate_refresh_token();
    let new_hash = hash_refresh_token(&new_plain)?;
    let new_expires_at = Some(DateTimeWithTimeZone::from(
        DateTime::from_timestamp(refresh_expiry_timestamp(&cfg), 0)
            .ok_or_else(|| ApiError::InternalError("Failed to compute expiry".into()))?,
    ));
    let _new_record =
        RefreshTokenRepository::create(&state.db, record.user_id, new_hash, new_expires_at)
            .await
            .map_err(|_| ApiError::InternalError("Failed to store refresh token".into()))?;
    let _ = RefreshTokenRepository::revoke_by_id(&state.db, record.id)
        .await
        .map_err(|_| ApiError::InternalError("Failed to revoke old refresh token".into()))?;

    // Return new tokens
    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        refresh_token: Some(new_plain),
        user: None,
    }))
}

/// Logout and revoke refresh tokens / session.
/// Client should present the refresh token to revoke it server-side.
/// This also increments the user's token_version to invalidate all access tokens.
pub async fn logout(
    body: web::Json<RefreshRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let req = body.into_inner();

    // Find the matching token by verifying against all non-revoked tokens
    let all_tokens = RefreshTokenRepository::find_all_active(&state.db)
        .await
        .map_err(|_| ApiError::InternalError("DB error".to_string()))?;

    let mut matching_record = None;
    for token in all_tokens {
        if let Ok(true) = verify_password(&token.token_hash, &req.refresh_token) {
            matching_record = Some(token);
            break;
        }
    }

    let record =
        matching_record.ok_or_else(|| ApiError::NotFound("Invalid refresh token".into()))?;

    // Revoke the refresh token
    let _ = RefreshTokenRepository::revoke_by_id(&state.db, record.id)
        .await
        .map_err(|_| ApiError::InternalError("Failed to revoke refresh token".into()))?;

    // Increment user's token_version to invalidate all access tokens
    UserService::increment_token_version(&state.db, record.user_id)
        .await
        .map_err(|_| ApiError::InternalError("Failed to invalidate tokens".into()))?;

    Ok(HttpResponse::NoContent().finish())
}

/// Return the currently authenticated user's public information.
///
/// Use the `AuthenticatedUser` extractor (Actix) which validates the access token.
pub async fn me(user: AuthenticatedUser) -> Result<HttpResponse, ApiError> {
    let resp = UserResponse {
        id: user.id,
        name: user.name,
        email: user.email,
    };
    Ok(HttpResponse::Ok().json(resp))
}

/// Revoke all refresh tokens for the authenticated user (global logout).
///
/// This is useful for "logout from all devices" functionality.
/// Also increments token_version to invalidate all access tokens.
pub async fn logout_all(
    user: AuthenticatedUser,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ApiError> {
    let count = RefreshTokenRepository::revoke_by_user(&state.db, user.id)
        .await
        .map_err(|_| ApiError::InternalError("Failed to revoke tokens".into()))?;

    // Increment token version to invalidate all access tokens
    UserService::increment_token_version(&state.db, user.id)
        .await
        .map_err(|_| ApiError::InternalError("Failed to invalidate tokens".into()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "All sessions revoked",
        "count": count
    })))
}

/// Admin endpoint to clean up expired refresh tokens.
///
/// In production, this should be called periodically via a cron job or background task.
/// For now, we expose it as an endpoint (should be protected with admin auth in production).
pub async fn cleanup_expired_tokens(state: web::Data<AppState>) -> Result<HttpResponse, ApiError> {
    let deleted = RefreshTokenRepository::delete_expired(&state.db)
        .await
        .map_err(|_| ApiError::InternalError("Failed to delete expired tokens".into()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Expired tokens cleaned up",
        "deleted": deleted
    })))
}
