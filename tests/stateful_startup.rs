#![cfg(feature = "stateful")]

#[tokio::test]
async fn db_migration_on_startup() {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let result = qimem::PostgresKeyStore::connect(&url).await;
        assert!(result.is_ok(), "stateful startup should run migrations");
    }
}
