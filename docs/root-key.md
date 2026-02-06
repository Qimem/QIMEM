# Root Key Strategy

The root key (`QIMEM_ROOT_KEY_B64`) is loaded once at boot and kept only in memory. Rotating
the root key is **destructive** because tenant master keys are wrapped with the root key; if
the root key changes without re-wrapping every tenant master key version, all wrapped master
keys become undecryptable and existing data cannot be recovered.

## Safe Rotation Requirements

1. Export all tenant master key versions (wrapped by the old root key).
2. Decrypt them with the old root key in a controlled environment.
3. Re-wrap each master key with the new root key.
4. Update `tenants.wrapped_master_key` and `tenant_master_key_versions` in-place.

If you cannot complete all steps, treat root key rotation as a permanent key-loss event.
