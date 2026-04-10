//! Application configuration loaded from environment variables.

use std::env;

/// Central application configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    // Server
    pub host: String,
    pub port: u16,

    // Database
    pub database_url: String,

    // JWT
    pub jwt_secret: String,
    pub jwt_access_expiry_secs: i64,
    pub jwt_refresh_expiry_secs: i64,

    // Environment
    pub environment: String,

    // Nmap
    pub nmap_binary_path: String,
    pub nmap_timeout_secs: u64,
    pub nmap_max_concurrent: usize,

    // Admin seed
    pub admin_username: String,
    pub admin_email: String,
    pub admin_password: String,
}

impl AppConfig {
    /// Load configuration from environment variables.
    /// Panics on missing required variables (fail-fast at startup).
    pub fn from_env() -> Self {
        Self {
            host: env::var("API_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("API_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .expect("API_PORT must be a valid port number"),

            database_url: env::var("DATABASE_URL")
                .expect("DATABASE_URL is required"),

            jwt_secret: env::var("JWT_SECRET")
                .expect("JWT_SECRET is required"),
            jwt_access_expiry_secs: env::var("JWT_ACCESS_TOKEN_EXPIRY_SECS")
                .unwrap_or_else(|_| "900".to_string())
                .parse()
                .expect("JWT_ACCESS_TOKEN_EXPIRY_SECS must be a number"),
            jwt_refresh_expiry_secs: env::var("JWT_REFRESH_TOKEN_EXPIRY_SECS")
                .unwrap_or_else(|_| "604800".to_string())
                .parse()
                .expect("JWT_REFRESH_TOKEN_EXPIRY_SECS must be a number"),

            environment: env::var("CDSIP_ENVIRONMENT")
                .unwrap_or_else(|_| "development".to_string()),

            nmap_binary_path: env::var("NMAP_BINARY_PATH")
                .unwrap_or_else(|_| "/usr/bin/nmap".to_string()),
            nmap_timeout_secs: env::var("NMAP_TIMEOUT_SECS")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .expect("NMAP_TIMEOUT_SECS must be a number"),
            nmap_max_concurrent: env::var("NMAP_MAX_CONCURRENT")
                .unwrap_or_else(|_| "2".to_string())
                .parse()
                .expect("NMAP_MAX_CONCURRENT must be a number"),

            admin_username: env::var("ADMIN_USERNAME")
                .unwrap_or_else(|_| "admin".to_string()),
            admin_email: env::var("ADMIN_EMAIL")
                .unwrap_or_else(|_| "admin@cdsip.local".to_string()),
            admin_password: env::var("ADMIN_PASSWORD")
                .unwrap_or_else(|_| "CHANGE_ME_admin_dev_password".to_string()),
        }
    }

    /// Validate that security-critical config is not using defaults.
    pub fn validate_security(&self) {
        if self.jwt_secret.contains("CHANGE_ME") {
            tracing::warn!("JWT_SECRET is using default value — CHANGE THIS IN PRODUCTION");
        }
        if self.admin_password.contains("CHANGE_ME") {
            tracing::warn!("ADMIN_PASSWORD is using default value — CHANGE THIS IN PRODUCTION");
        }
        if self.environment == "production" && self.jwt_secret.contains("CHANGE_ME") {
            panic!("FATAL: Cannot start in production with default JWT_SECRET");
        }
    }
}
