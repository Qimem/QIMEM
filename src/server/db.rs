use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::server::kms::{AuditLogEntry, TenantKeyVersion, TenantRecord};

#[derive(Clone, Debug)]
pub struct DbState {
    pool: PgPool,
}

impl DbState {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn insert_tenant(&self, tenant: &TenantRecord) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO tenants (id, name, wrapped_master_key, key_version, crypto_policy_version, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(tenant.id)
        .bind(&tenant.name)
        .bind(&tenant.wrapped_master_key)
        .bind(tenant.key_version as i64)
        .bind(tenant.crypto_policy_version as i64)
        .bind(tenant.created_at)
        .bind(tenant.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn insert_master_key_version(
        &self,
        tenant_id: Uuid,
        version: i64,
        wrapped_master_key: &[u8],
        created_at: chrono::NaiveDateTime,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO tenant_master_key_versions (tenant_id, version, wrapped_master_key, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(tenant_id)
        .bind(version)
        .bind(wrapped_master_key)
        .bind(created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn fetch_tenant(&self, tenant_id: Uuid) -> Result<TenantRecord, sqlx::Error> {
        let row = sqlx::query(
            "SELECT id, name, wrapped_master_key, key_version, crypto_policy_version, created_at, updated_at
             FROM tenants WHERE id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(TenantRecord {
            id: row.get("id"),
            name: row.get("name"),
            wrapped_master_key: row.get("wrapped_master_key"),
            key_version: row.get::<i64, _>("key_version") as u32,
            crypto_policy_version: row.get::<i64, _>("crypto_policy_version") as u32,
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    pub async fn fetch_master_key_version(
        &self,
        tenant_id: Uuid,
        version: i64,
    ) -> Result<TenantKeyVersion, sqlx::Error> {
        let row = sqlx::query(
            "SELECT tenant_id, version, wrapped_master_key, created_at
             FROM tenant_master_key_versions WHERE tenant_id = $1 AND version = $2",
        )
        .bind(tenant_id)
        .bind(version)
        .fetch_one(&self.pool)
        .await?;

        Ok(TenantKeyVersion {
            tenant_id: row.get("tenant_id"),
            version: row.get::<i64, _>("version") as u32,
            wrapped_master_key: row.get("wrapped_master_key"),
            created_at: row.get("created_at"),
        })
    }

    pub async fn fetch_all_master_key_versions(
        &self,
    ) -> Result<Vec<TenantKeyVersion>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT tenant_id, version, wrapped_master_key, created_at FROM tenant_master_key_versions",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| TenantKeyVersion {
                tenant_id: row.get("tenant_id"),
                version: row.get::<i64, _>("version") as u32,
                wrapped_master_key: row.get("wrapped_master_key"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    pub async fn update_master_key_version(
        &self,
        tenant_id: Uuid,
        version: i64,
        wrapped_master_key: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE tenant_master_key_versions SET wrapped_master_key = $1 WHERE tenant_id = $2 AND version = $3",
        )
        .bind(wrapped_master_key)
        .bind(tenant_id)
        .bind(version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_tenant_wrapped_master_key(
        &self,
        tenant_id: Uuid,
        wrapped_master_key: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE tenants SET wrapped_master_key = $1 WHERE id = $2")
            .bind(wrapped_master_key)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_tenant_wrapped_master_key_for_version(
        &self,
        tenant_id: Uuid,
        key_version: i64,
        wrapped_master_key: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE tenants SET wrapped_master_key = $1 WHERE id = $2 AND key_version = $3",
        )
        .bind(wrapped_master_key)
        .bind(tenant_id)
        .bind(key_version)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_tenant_key_version(
        &self,
        tenant_id: Uuid,
        key_version: i64,
        updated_at: chrono::NaiveDateTime,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE tenants SET key_version = $1, updated_at = $2 WHERE id = $3")
            .bind(key_version)
            .bind(updated_at)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn insert_pq_key(
        &self,
        tenant_id: Uuid,
        algorithm: &str,
        public_key: &[u8],
        wrapped_private_key: &[u8],
        created_at: chrono::NaiveDateTime,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO tenant_pq_keys (tenant_id, algorithm, public_key, wrapped_private_key, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant_id)
        .bind(algorithm)
        .bind(public_key)
        .bind(wrapped_private_key)
        .bind(created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_audit_log(&self, entry: &AuditLogEntry) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO audit_logs (id, tenant_id, event_type, event_hash, prev_hash, metadata, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(entry.id)
        .bind(entry.tenant_id)
        .bind(&entry.event_type)
        .bind(&entry.event_hash)
        .bind(&entry.prev_hash)
        .bind(&entry.metadata)
        .bind(entry.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn fetch_latest_audit_hash(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<Vec<u8>>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT event_hash FROM audit_logs WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|value| value.get("event_hash")))
    }

    pub async fn fetch_audit_logs(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditLogEntry>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, event_type, event_hash, prev_hash, metadata, created_at
             FROM audit_logs WHERE tenant_id = $1
             ORDER BY created_at DESC
             LIMIT $2",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| AuditLogEntry {
                id: row.get("id"),
                tenant_id: row.get("tenant_id"),
                event_type: row.get("event_type"),
                event_hash: row.get("event_hash"),
                prev_hash: row.get("prev_hash"),
                metadata: row.get("metadata"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    pub async fn insert_root_key_rotation(
        &self,
        id: Uuid,
        started_at: chrono::NaiveDateTime,
        completed_at: Option<chrono::NaiveDateTime>,
        tenant_count: i64,
        dry_run: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO root_key_rotations (id, started_at, completed_at, tenant_count, dry_run)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(started_at)
        .bind(completed_at)
        .bind(tenant_count)
        .bind(dry_run)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
