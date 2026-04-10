//! Authentication extractor — validates JWT and extracts user claims.

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use uuid::Uuid;

use cdsip_domain_models::user::Claims;
use crate::errors::AppError;
use crate::extractors::AppState;

/// Authenticated user extracted from JWT bearer token.
/// Use this as an extractor in route handlers to enforce authentication.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
}

impl<S> FromRequestParts<S> for AuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Extract token from Authorization header
        let token = extract_bearer_token(&parts.headers)?;

        // Decode and validate JWT
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(app_state.config.jwt_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|e| AppError::Unauthorized(format!("Invalid token: {e}")))?;

        let claims = token_data.claims;

        Ok(AuthUser {
            user_id: claims.sub,
            username: claims.username,
            role: claims.role,
        })
    }
}

/// Extract bearer token from Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    let auth_header = headers
        .get("Authorization")
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?
        .to_str()
        .map_err(|_| AppError::Unauthorized("Invalid Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized(
            "Authorization header must use Bearer scheme".to_string(),
        ));
    }

    Ok(auth_header[7..].to_string())
}

/// Require a specific role. Returns Forbidden if the user doesn't have it.
pub fn require_role(user: &AuthUser, allowed_roles: &[&str]) -> Result<(), AppError> {
    if allowed_roles.contains(&user.role.as_str()) {
        Ok(())
    } else {
        Err(AppError::Forbidden(format!(
            "Role '{}' is not authorized for this action. Required: {:?}",
            user.role, allowed_roles
        )))
    }
}

/// Require write access (admin or security_analyst).
pub fn require_write(user: &AuthUser) -> Result<(), AppError> {
    require_role(user, &["admin", "security_analyst"])
}

/// Require admin access.
pub fn require_admin(user: &AuthUser) -> Result<(), AppError> {
    require_role(user, &["admin"])
}

/// Require audit access (admin or auditor).
pub fn require_audit_access(user: &AuthUser) -> Result<(), AppError> {
    require_role(user, &["admin", "auditor"])
}
