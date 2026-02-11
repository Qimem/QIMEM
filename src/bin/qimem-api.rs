use std::env;
use std::net::SocketAddr;

use axum::middleware;
use dotenvy::dotenv;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use qimem::server::{policy_middleware, router, AppState, AuthConfig, KmsService, PolicyConfig};

#[derive(Debug, thiserror::Error)]
enum ApiStartupError {
    #[error("Missing QIMEM authentication configuration: {0}")]
    Auth(#[from] qimem::server::auth::AuthError),
    #[error("Missing or invalid KMS configuration")]
    Kms,
    #[error("Failed to build rate limiter")]
    RateLimiter,
    #[error("Invalid host/port")]
    Addr,
    #[error("Failed to bind listener: {0}")]
    Bind(std::io::Error),
    #[error("Server error: {0}")]
    Serve(std::io::Error),
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), ApiStartupError> {
    dotenv().ok();

    let host = env::var("QIMEM_API_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = env::var("QIMEM_API_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);

    let auth = AuthConfig::from_env()?;
    let policy = PolicyConfig::from_env();
    let kms = KmsService::from_env()
        .await
        .map_err(|_| ApiStartupError::Kms)?;

    let state = AppState { auth, policy, kms };

    let rate_limit = GovernorConfigBuilder::default()
        .burst_size(60)
        .per_second(1)
        .use_headers()
        .finish()
        .ok_or(ApiStartupError::RateLimiter)?;

    let app = router(state.clone())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_origin(Any).allow_headers(Any))
        .layer(GovernorLayer {
            config: rate_limit.into(),
        })
        .layer(middleware::from_fn_with_state(
            state.policy.clone(),
            policy_middleware,
        ));

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .map_err(|_| ApiStartupError::Addr)?;
    println!("QIMEM API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(ApiStartupError::Bind)?;
    axum::serve(listener, app)
        .await
        .map_err(ApiStartupError::Serve)
}
