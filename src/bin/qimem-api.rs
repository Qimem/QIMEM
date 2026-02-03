use std::env;
use std::net::SocketAddr;

use axum::middleware;
use tower_governor::{GovernorConfigBuilder, GovernorLayer};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use qimem::server::{policy_middleware, router, AppState, AuthConfig, PolicyConfig};

#[tokio::main]
async fn main() {
    let host = env::var("QIMEM_API_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = env::var("QIMEM_API_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);

    let auth = AuthConfig::from_env().expect("Missing Better Auth configuration");
    let policy = PolicyConfig::from_env();

    let state = AppState { auth, policy };

    let rate_limit = GovernorConfigBuilder::default()
        .burst_size(60)
        .per_second(1)
        .use_headers()
        .finish()
        .expect("Failed to build rate limiter");

    let app = router(state.clone())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new().allow_origin(Any).allow_headers(Any))
        .layer(GovernorLayer { config: rate_limit })
        .layer(middleware::from_fn_with_state(state.policy.clone(), policy_middleware));

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid host/port");
    println!("QIMEM API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server error");
}
