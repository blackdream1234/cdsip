use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::env;
use tower::ServiceExt;

use cdsip_api::config::AppConfig;
use cdsip_api::server::{build_app_state, build_router};

#[tokio::test]
async fn test_unauthenticated_requests_return_401() {
    // Skip if no DATABASE_URL, which means we aren't in CI or a full environment
    if env::var("DATABASE_URL").is_err() {
        println!("Skipping DB integration test due to missing DATABASE_URL");
        return;
    }

    // Set a mock secret for testing
    unsafe {
        env::set_var("JWT_SECRET", "test_secret_1234567890_min_32_chars");
    }

    let config = AppConfig::from_env();
    let state = build_app_state(config).await;
    let app = build_router(state);

    let endpoints_requiring_auth = vec![
        "/api/v1/auth/me",
        "/api/v1/assets",
        "/api/v1/scan-jobs",
        "/api/v1/policies",
        "/api/v1/audit",
    ];

    for endpoint in endpoints_requiring_auth {
        let req = Request::builder()
            .uri(endpoint)
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Endpoint {} should require authentication",
            endpoint
        );
    }
}

#[tokio::test]
async fn test_health_check_public() {
    if env::var("DATABASE_URL").is_err() {
        return;
    }

    unsafe {
        env::set_var("JWT_SECRET", "test_secret_1234567890_min_32_chars");
    }
    
    let config = AppConfig::from_env();
    let state = build_app_state(config).await;
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/v1/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
