use std::sync::{Arc, RwLock};

use qimem::config::Config;
use qimem::platform_api::{router, PlatformState};
use qimem::qauth::QAuthService;
use qimem::{InMemoryKeyStore, KeyStore, QimemError};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Err(err) = run().await {
        eprintln!("{{\"error\":\"{err}\"}}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), QimemError> {
    let config = Config::from_env()?;
    let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::default());
    let qauth = QAuthService::new();

    let app = router(PlatformState {
        qauth,
        store,
        plugins: Arc::new(RwLock::new(Vec::new())),
    });

    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|err| QimemError::Config(format!("bind error: {err}")))?;
    axum::serve(listener, app)
        .await
        .map_err(|err| QimemError::Config(format!("server error: {err}")))
}
