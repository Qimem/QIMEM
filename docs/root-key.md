# Root Key Strategy

## Purpose
The root key (`QIMEM_ROOT_KEY_B64`) is the top-level wrapping key. It never encrypts payloads
directly; it only wraps tenant master keys, which in turn wrap data encryption keys (DEKs).

## Threat Model
If an attacker obtains the root key they can unwrap all tenant master keys and decrypt any
wrapped DEKs. If the root key is lost or corrupted, **all wrapped master keys become
undecryptable**, which permanently locks existing ciphertexts.

## Source and Handling
- Source is configured via `QIMEM_ROOT_KEY_SOURCE` (`env` or `secret-manager`).
- The root key must be provided in base64 via `QIMEM_ROOT_KEY_B64` when the source is `env`.
- The application fails fast if the root key is missing or invalid.
- The root key is never stored in Postgres, never logged, never returned by any API endpoint,
  and exists only in memory at runtime.

## Operational Guidance
- **Backup** the root key in a secure secret store with access controls and audit logging.
- Limit access to the smallest possible operator set.
- Treat the key as a production secret with rotation procedures and disaster recovery drills.

## Root Rotation (Destructive)
Root rotation is intentionally destructive and requires an explicit CLI command with
`ENABLE_DESTRUCTIVE_ROTATION=true` and the confirmation string
`CONFIRM_ROOT_ROTATION_AND_DATA_REENCRYPTION`.

Rotation must:
1. Decrypt every tenant master key version using the old root key.
2. Re-wrap each master key version with the new root key.
3. Update `tenants.wrapped_master_key` and `tenant_master_key_versions`.
4. Log audit entries before and after rotation and persist rotation timestamps.

If any step fails, **data is unrecoverable** until all master key versions are rewrapped.
Downtime is expected during the rewrap process.
