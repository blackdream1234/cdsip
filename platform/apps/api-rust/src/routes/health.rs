//! Health check endpoint — unauthenticated.

use axum::Json;
use serde_json::{json, Value};

pub async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "cdsip-api",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
