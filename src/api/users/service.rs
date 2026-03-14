use crate::api::users::dto::{CreateUser, UpdateUser, UserResponse};
use crate::api::users::repository::UserRepository;
use crate::shared::errors::api_errors::ApiError;
use crate::shared::models::users::user::ActiveModel;
use crate::shared::utils::auth_utils::{AuthConfig, create_jwt, hash_password, verify_password};
use chrono::Utc;
use sea_orm::{DatabaseConnection, Set};
use uuid::Uuid;

/// Service layer for user-related business logic.
///
/// This file adjusts register/login to set password fields directly on the ActiveModel
/// (so we can use the repository's existing `insert` method) and fixes incorrect
/// Option handling for password_hash / token_version (they are stored as concrete types
/// in the current entity).
pub struct UserService;

impl UserService {
    /// Register a new user with a password.
    ///
    /// Production considerations implemented here:
    /// - Validate inputs (non-empty, password length)
    /// - Hash password using Argon2 (delegated via `hash_password`)
    /// - Ensure email uniqueness (DB unique constraint recommended)
    /// - Store password hash and initial token_version/is_active on the ActiveModel
    pub async fn register_user(
        db: &DatabaseConnection,
        input: CreateUser,
        password: String,
    ) -> Result<Uuid, ApiError> {
        // Basic validation
        if input.name.trim().is_empty() {
            return Err(ApiError::BadRequest("Name cannot be empty".into()));
        }
        if input.email.trim().is_empty() {
            return Err(ApiError::BadRequest("Email cannot be empty".into()));
        }
        if password.len() < 8 {
            return Err(ApiError::BadRequest(
                "Password must be at least 8 characters".into(),
            ));
        }

        // Check uniqueness
        if UserRepository::find_by_email(db, &input.email)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?
            .is_some()
        {
            return Err(ApiError::Conflict("Email already exists".into()));
        }

        // Hash password
        let password_hash = hash_password(&password)?;

        // Prepare ActiveModel for insertion with auth fields set directly.
        let id = Uuid::new_v4();
        let active = ActiveModel {
            id: Set(id),
            name: Set(input.name),
            email: Set(input.email),
            // entity defines `password_hash: String`, `token_version: i32`, `is_active: bool`
            password_hash: Set(password_hash),
            token_version: Set(0),
            is_active: Set(true),
            created_at: Set(Some(Utc::now().into())),
            ..Default::default()
        };

        // Use existing repository insert to persist the model (no insert_with_password helper needed).
        UserRepository::insert(db, active)
            .await
            .map_err(|e| ApiError::InternalError(format!("DB insert failed: {}", e)))?;

        Ok(id)
    }

    /// Authenticate a user and return a JWT.
    ///
    /// Implementation notes:
    /// - The repository returns the user's stored password hash and token version.
    /// - We verify the password using Argon2 (via `verify_password`).
    /// - On success, we create a signed JWT using `create_jwt`.
    /// - Token versioning (`tv`) is embedded in the token so that changing a user's
    ///   `token_version` in the DB can immediately invalidate previously issued tokens.
    pub async fn login(
        db: &DatabaseConnection,
        email: &str,
        password: &str,
    ) -> Result<String, ApiError> {
        if email.trim().is_empty() || password.is_empty() {
            return Err(ApiError::BadRequest(
                "Email and password must be provided".into(),
            ));
        }

        // Fetch user (repository returns the full model including password_hash and token_version)
        let user = UserRepository::find_by_email(db, email)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("Invalid Email Address".into()))?;

        // Extract password_hash and token_version directly (concrete types in entity)
        let stored_hash: String = user.password_hash;
        let tv: i32 = user.token_version;

        // Verify password
        let ok = verify_password(&stored_hash, password)?;
        if !ok {
            return Err(ApiError::NotFound("Invalid Password".into()));
        }

        // Build auth config from env (JWT secret, expiry)
        let cfg = AuthConfig::get();

        // Create token
        let token = create_jwt(user.id, tv, &cfg)?;

        Ok(token)
    }

    pub async fn list_users(db: &DatabaseConnection) -> Result<Vec<UserResponse>, ApiError> {
        let users = UserRepository::find_all(db)
            .await
            .map_err(|_| ApiError::InternalError("DB error".to_string()))?;

        Ok(users
            .into_iter()
            .map(|m| UserResponse {
                id: m.id,
                name: m.name,
                email: m.email,
            })
            .collect())
    }

    pub async fn get_user(db: &DatabaseConnection, id: Uuid) -> Result<UserResponse, ApiError> {
        if id == Uuid::nil() {
            return Err(ApiError::BadRequest("Invalid UUID".into()));
        }

        let user = UserRepository::find_by_id(db, id)
            .await
            .map_err(|_| ApiError::InternalError("DB error".to_string()))?
            .ok_or_else(|| ApiError::NotFound(format!("User {} not found", id)))?;

        Ok(UserResponse {
            id: user.id,
            name: user.name,
            email: user.email,
        })
    }

    pub async fn update_user(
        db: &DatabaseConnection,
        id: Uuid,
        input: UpdateUser,
    ) -> Result<UserResponse, ApiError> {
        let existing = UserRepository::find_by_id(db, id)
            .await
            .map_err(|_| ApiError::InternalError("DB error".to_string()))?
            .ok_or_else(|| ApiError::NotFound(format!("User {} not found", id)))?;

        let mut active: ActiveModel = existing.into();

        if let Some(name) = input.name {
            if name.trim().is_empty() {
                return Err(ApiError::BadRequest("Name cannot be empty".into()));
            }
            active.name = Set(name);
        }

        if let Some(email) = input.email {
            if email.trim().is_empty() {
                return Err(ApiError::BadRequest("Email cannot be empty".into()));
            }
            if UserRepository::find_by_email(db, &email)
                .await
                .map_err(|_| ApiError::InternalError("DB error".to_string()))?
                .filter(|u| u.id != id)
                .is_some()
            {
                return Err(ApiError::Conflict("Email already exists".into()));
            }
            active.email = Set(email);
        }

        let updated = UserRepository::update(db, active)
            .await
            .map_err(|_| ApiError::InternalError("DB update failed".to_string()))?;

        Ok(UserResponse {
            id: updated.id,
            name: updated.name,
            email: updated.email,
        })
    }

    pub async fn delete_user(db: &DatabaseConnection, id: Uuid) -> Result<(), ApiError> {
        if id == Uuid::nil() {
            return Err(ApiError::BadRequest("Invalid UUID".into()));
        }

        let rows = UserRepository::delete(db, id)
            .await
            .map_err(|_| ApiError::InternalError("DB delete failed".to_string()))?;

        if rows == 0 {
            return Err(ApiError::NotFound(format!("User {} not found", id)));
        }

        Ok(())
    }

    /// Increment a user's token_version to invalidate all issued access tokens.
    /// This is useful for logout or security events (password change, etc).
    pub async fn increment_token_version(
        db: &DatabaseConnection,
        id: Uuid,
    ) -> Result<(), ApiError> {
        let user = UserRepository::find_by_id(db, id)
            .await
            .map_err(|_| ApiError::InternalError("DB error".to_string()))?
            .ok_or_else(|| ApiError::NotFound(format!("User {} not found", id)))?;

        let mut active: ActiveModel = user.into();
        active.token_version = Set(active.token_version.unwrap() + 1);

        UserRepository::update(db, active)
            .await
            .map_err(|_| ApiError::InternalError("DB update failed".to_string()))?;

        Ok(())
    }

    // Similarly implement update, delete, get, list with validation
}
