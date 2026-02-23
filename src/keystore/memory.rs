use std::collections::HashMap;
use std::sync::RwLock;

use uuid::Uuid;

use crate::error::{QimemError, Result};
use crate::keystore::{generate_key_material, KeyMaterial, KeyMetadata, KeyStore};

#[derive(Debug, Clone)]
struct StoredKey {
    metadata: KeyMetadata,
    material: Vec<u8>,
}

/// In-memory key store.
#[derive(Debug, Default)]
pub struct InMemoryKeyStore {
    keys: RwLock<HashMap<Uuid, StoredKey>>,
    lineages: RwLock<HashMap<Uuid, Uuid>>,
}

impl KeyStore for InMemoryKeyStore {
    fn create_key(&self) -> Result<KeyMetadata> {
        let key_id = Uuid::new_v4();
        let lineage_id = key_id;
        let metadata = KeyMetadata {
            key_id,
            lineage_id,
            version: 1,
            active: true,
        };
        let stored = StoredKey {
            metadata: metadata.clone(),
            material: generate_key_material().to_vec(),
        };
        self.keys
            .write()
            .map_err(|_| QimemError::Config("poisoned lock".to_string()))?
            .insert(key_id, stored);
        self.lineages
            .write()
            .map_err(|_| QimemError::Config("poisoned lock".to_string()))?
            .insert(lineage_id, key_id);
        Ok(metadata)
    }

    fn get_key(&self, key_id: Uuid) -> Result<KeyMaterial> {
        let keys = self
            .keys
            .read()
            .map_err(|_| QimemError::Config("poisoned lock".to_string()))?;
        let stored = keys.get(&key_id).ok_or(QimemError::KeyNotFound(key_id))?;
        Ok(KeyMaterial {
            key_id,
            material: zeroize::Zeroizing::new(stored.material.clone()),
            active: stored.metadata.active,
        })
    }

    fn rotate_key(&self, key_id: Uuid) -> Result<KeyMetadata> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| QimemError::Config("poisoned lock".to_string()))?;
        let old = keys
            .get_mut(&key_id)
            .ok_or(QimemError::KeyNotFound(key_id))?;
        old.metadata.active = false;

        let new_id = Uuid::new_v4();
        let metadata = KeyMetadata {
            key_id: new_id,
            lineage_id: old.metadata.lineage_id,
            version: old.metadata.version + 1,
            active: true,
        };
        let new = StoredKey {
            metadata: metadata.clone(),
            material: generate_key_material().to_vec(),
        };
        keys.insert(new_id, new);
        self.lineages
            .write()
            .map_err(|_| QimemError::Config("poisoned lock".to_string()))?
            .insert(metadata.lineage_id, new_id);
        Ok(metadata)
    }
}
