use std::process::Command;
use std::time::Duration;

use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers::ImageExt;
use testcontainers_modules::postgres::Postgres;

use qimem::server::db::DbState;

pub struct TestDb {
    // Keep container alive for whole async test execution.
    _container: testcontainers::ContainerAsync<Postgres>,
    pub db: DbState,
    #[allow(dead_code)]
    pub database_url: String,
}

pub fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub async fn setup_test_db() -> TestDb {
    // Start a dedicated Postgres container with bounded startup timeout.
    let container = Postgres::default()
        .with_tag("15-alpine")
        .with_startup_timeout(Duration::from_secs(90))
        .start()
        .await
        .expect("start postgres test container");

    // Retrieve runtime host and mapped port.
    let host = container
        .get_host()
        .await
        .expect("resolve postgres host")
        .to_string();
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("resolve postgres port");

    // IMPORTANT: disable SSL against local testcontainers postgres to avoid SSLRequest issues.
    let database_url =
        format!("postgres://postgres:postgres@{host}:{port}/postgres?sslmode=disable");

    // Explicit readiness check: retry connection + lightweight health query.
    let pool = connect_with_retry(&database_url, 30, Duration::from_millis(300)).await;
    wait_for_healthcheck(&pool, 30, Duration::from_millis(250)).await;

    apply_schema(&pool).await;
    let db = DbState::connect(&database_url).await.expect("db state");
    TestDb {
        _container: container,
        db,
        database_url,
    }
}

async fn connect_with_retry(database_url: &str, attempts: usize, delay: Duration) -> PgPool {
    let mut last_err = None;
    for _ in 0..attempts {
        match PgPool::connect(database_url).await {
            Ok(pool) => return pool,
            Err(err) => {
                last_err = Some(err);
                tokio::time::sleep(delay).await;
            }
        }
    }
    panic!("connect db after retries: {:?}", last_err);
}

async fn wait_for_healthcheck(pool: &PgPool, attempts: usize, delay: Duration) {
    let mut last_err = None;
    for _ in 0..attempts {
        match sqlx::query_scalar::<_, i64>("SELECT 1::BIGINT")
            .fetch_one(pool)
            .await
        {
            Ok(_) => return,
            Err(err) => {
                last_err = Some(err);
                tokio::time::sleep(delay).await;
            }
        }
    }
    panic!("postgres healthcheck failed after retries: {:?}", last_err);
}

async fn apply_schema(pool: &PgPool) {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .expect("apply migrations");
}
