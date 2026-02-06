use crate::server::kms::{rotate_root_key, KmsError, RootRotationOptions, RootRotationSummary};

pub async fn execute_root_rotation(
    enable_destructive: bool,
    confirmation: String,
    dry_run: bool,
) -> Result<RootRotationSummary, KmsError> {
    rotate_root_key(RootRotationOptions {
        enable_destructive,
        confirmation,
        dry_run,
    })
    .await
}
