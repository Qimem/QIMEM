use std::env;

use dotenvy::dotenv;
use qimem::server::root_rotation::execute_root_rotation;

#[tokio::main]
async fn main() {
    env_logger::init();
    dotenv().ok();

    let dry_run = env::args().any(|arg| arg == "--dry-run");
    let root_rotation_enabled = env::var("QIMEM_ROOT_ROTATION_ENABLED")
        .map(|value| value == "true" || value == "1")
        .unwrap_or(false);

    if !root_rotation_enabled {
        log::info!("Root rotation disabled; skipping");
        return;
    }

    let enable_destructive = env::var("ENABLE_DESTRUCTIVE_ROTATION")
        .map(|value| value == "true" || value == "1")
        .unwrap_or(false);
    let confirmation = env::var("QIMEM_ROOT_ROTATION_CONFIRMATION").unwrap_or_default();

    match execute_root_rotation(enable_destructive, confirmation, dry_run).await {
        Ok(summary) => {
            println!(
                "Root rotation completed. rotation_id={} tenants={} dry_run={}",
                summary.rotation_id, summary.tenant_count, summary.dry_run
            );
        }
        Err(err) => {
            log::warn!("Root rotation skipped/failed: {err}");
        }
    }
}
