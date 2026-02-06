# Key Rotation Plan

## Objectives
- Reduce blast radius of key compromise.
- Enable cryptographic agility.
- Preserve decrypt availability during migration.

## Rotation Types

### Root Key Rotation
- Per environment (prod/staging).
- Requires rewrapping all tenant master keys.
- Performed during controlled maintenance window.

### Tenant Master Key Rotation
- Triggered by schedule or policy (e.g., quarterly).
- New TMK version generated and wrapped.
- DEK wrapping uses latest version by default.

### DEK Rotation
- For high-sensitivity data or policy requirements.
- Re-encrypt payloads with new DEK and update metadata.

## Execution Steps (TMK)
1. Create new TMK version for tenant.
2. Update tenant record with new key version.
3. New wraps use latest key version.
4. Optional background rewrap of stored DEKs.
5. Mark old key version as deprecated; deny new wraps.
6. Final revoke after compliance window.

## Operational Controls
- Rotation events recorded in audit logs.
- APIs require elevated scope for rotation.
- SDK can detect key version changes and rewrap.
