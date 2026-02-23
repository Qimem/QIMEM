use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::error::{QimemError, Result};
use crate::keystore::{generate_key_material, KeyMaterial, KeyMetadata, KeyStore};

/// Postgres key store.
#[derive(Debug, Clone)]
pub struct PostgresKeyStore {
    pool: PgPool,
}

impl PostgresKeyStore {
    /// Connects and runs migrations.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url).await?;
        sqlx::migrate!("./migrations").run(&pool).await.map_err(|err| QimemError::Config(format!("migration failed: {err}")))?;
        Ok(Self { pool })
    }
}

impl KeyStore for PostgresKeyStore {
    fn create_key(&self) -> Result<KeyMetadata> {
        let key_id = Uuid::new_v4();
        let lineage_id = key_id;
        let material = generate_key_material();
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            sqlx::query("INSERT INTO keys (key_id, lineage_id, version, active, material) VALUES ($1,$2,$3,$4,$5)")
                .bind(key_id)
                .bind(lineage_id)
                .bind(1_i32)
                .bind(true)
                .bind(material.as_slice())
                .execute(&self.pool)
                .await?;
            Ok::<(), sqlx::Error>(())
        })?;
        Ok(KeyMetadata {
            key_id,
            lineage_id,
            version: 1,
            active: true,
        })
    }

    fn get_key(&self, key_id: Uuid) -> Result<KeyMaterial> {
        let rt = tokio::runtime::Handle::current();
        let row = rt.block_on(async {
            sqlx::query("SELECT material, active FROM keys WHERE key_id=$1")
                .bind(key_id)
                .fetch_optional(&self.pool)
                .await
        })?;
        let row = row.ok_or(QimemError::KeyNotFound(key_id))?;
        let material: Vec<u8> = row.try_get("material")?;
        let active: bool = row.try_get("active")?;
        Ok(KeyMaterial {
            key_id,
            material: zeroize::Zeroizing::new(material),
            active,
        })
    }

    fn rotate_key(&self, key_id: Uuid) -> Result<KeyMetadata> {
        let new_id = Uuid::new_v4();
        let material = generate_key_material();
        let rt = tokio::runtime::Handle::current();
        let metadata = rt.block_on(async {
            let mut tx = self.pool.begin().await?;
            let row = sqlx::query("SELECT lineage_id, version FROM keys WHERE key_id=$1")
                .bind(key_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(QimemError::KeyNotFound(key_id))?;
            let lineage_id: Uuid = row.try_get("lineage_id")?;
            let version: i32 = row.try_get("version")?;
            sqlx::query("UPDATE keys SET active=false WHERE key_id=$1")
                .bind(key_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO keys (key_id, lineage_id, version, active, material) VALUES ($1,$2,$3,$4,$5)")
                .bind(new_id)
                .bind(lineage_id)
                .bind(version + 1)
                .bind(true)
                .bind(material.as_slice())
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok::<KeyMetadata, QimemError>(KeyMetadata { key_id: new_id, lineage_id, version: version + 1, active: true })
        })?;
        Ok(metadata)
    }
}
