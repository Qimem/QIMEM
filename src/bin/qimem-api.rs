use std::sync::Arc;

use qimem::api::{router, AppState};
use qimem::config::{Config, Mode};
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

    let store: Arc<dyn KeyStore> = match config.mode {
        Mode::Stateless => Arc::new(InMemoryKeyStore::default()),
        Mode::Stateful => {
            #[cfg(feature = "stateful")]
            {
                let url = config.database_url.as_deref().ok_or_else(|| {
                    QimemError::Config("DATABASE_URL is required for stateful mode".to_string())
                })?;
                Arc::new(qimem::PostgresKeyStore::connect(url).await?)
            }
            #[cfg(not(feature = "stateful"))]
            {
                return Err(QimemError::Config(
                    "stateful mode requires the `stateful` feature".to_string(),
                ));
            }
        }
    };

    let app = router(AppState { store });
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|err| QimemError::Config(format!("bind error: {err}")))?;
    axum::serve(listener, app)
        .await
        .map_err(|err| QimemError::Config(format!("server error: {err}")))
}
