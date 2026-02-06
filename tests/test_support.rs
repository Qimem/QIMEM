use sqlx::PgPool;
use testcontainers::clients::Cli;
use testcontainers::images::postgres::Postgres;
use testcontainers::Container;

use qimem::server::db::DbState;

pub struct TestDb<'a> {
    _container: Container<'a, Postgres>,
    pub db: DbState,
    pub database_url: String,
}

pub async fn setup_test_db<'a>() -> TestDb<'a> {
    let docker = Box::leak(Box::new(Cli::default()));
    let container = docker.run(Postgres::default());
    let port = container.get_host_port_ipv4(5432);
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{}/postgres", port);
    let pool = PgPool::connect(&database_url).await.expect("connect db");
    apply_schema(&pool).await;
    let db = DbState::connect(&database_url).await.expect("db state");
    TestDb {
        _container: container,
        db,
        database_url,
    }
}

async fn apply_schema(pool: &PgPool) {
    let schema = include_str!("../docs/schema.sql");
    for statement in schema.split(';') {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            continue;
        }
        let _ = sqlx::query(trimmed).execute(pool).await;
    }
}
