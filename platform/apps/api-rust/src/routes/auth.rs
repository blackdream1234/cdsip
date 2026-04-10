//! Authentication routes — login, logout, me, refresh.

use axum::extract::State;
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use uuid::Uuid;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use validator::Validate;

use cdsip_domain_models::user::{
    AuthTokens, Claims, LoginRequest, User, UserPublic,
};
use crate::errors::AppError;
use crate::extractors::AppState;
use crate::extractors::auth::AuthUser;

/// POST /api/v1/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthTokens>, AppError> {
    req.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    let request_id = Uuid::now_v7();

    // Find user by username
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE username = $1 AND is_active = true",
    )
    .bind(&req.username)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;

    // Verify password
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| AppError::Internal("Password hash parse error".to_string()))?;

    Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?;

    // Generate JWT
    let now = Utc::now();
    let jti = Uuid::now_v7();

    let claims = Claims {
        sub: user.id,
        username: user.username.clone(),
        role: user.role.clone(),
        iat: now.timestamp() as usize,
        exp: (now.timestamp() + state.config.jwt_access_expiry_secs) as usize,
        jti,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )?;

    // Audit log
    state
        .audit_logger
        .log_login(user.id, &user.role, request_id, None, true)
        .await?;

    Ok(Json(AuthTokens {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.jwt_access_expiry_secs,
    }))
}

/// POST /api/v1/auth/logout
pub async fn logout(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let request_id = Uuid::now_v7();

    state
        .audit_logger
        .log_logout(auth.user_id, &auth.role, request_id)
        .await?;

    Ok(Json(serde_json::json!({"message": "Logged out"})))
}

/// GET /api/v1/auth/me
pub async fn me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<UserPublic>, AppError> {
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1",
    )
    .bind(auth.user_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(UserPublic::from(user)))
}

/// Seed the admin user on first startup if no users exist.
pub async fn seed_admin_user(state: &AppState) -> Result<(), AppError> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&state.pool)
        .await?;

    if count.0 > 0 {
        tracing::info!("Users already exist, skipping admin seed");
        return Ok(());
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(state.config.admin_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Failed to hash admin password: {e}")))?
        .to_string();

    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, role, is_active)
        VALUES ($1, $2, $3, $4, 'admin', true)
        ON CONFLICT (username) DO NOTHING
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(&state.config.admin_username)
    .bind(&state.config.admin_email)
    .bind(&password_hash)
    .execute(&state.pool)
    .await?;

    tracing::info!(
        username = %state.config.admin_username,
        email = %state.config.admin_email,
        "Admin user seeded"
    );

    Ok(())
}
