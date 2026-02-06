# Cryptographic Lifecycle

## Key Types
- **Root Key**: Environment-level root key stored in HSM/KMS.
- **Tenant Master Key (TMK)**: Unique per tenant, encrypted by root key.
- **Data Encryption Key (DEK)**: Ephemeral or short-lived key used for payload encryption.

## Lifecycle Stages

### 1) Provisioning
- Create tenant record.
- Generate TMK within secure boundary.
- Wrap TMK with root key and store.

### 2) Usage
- SDK generates DEK locally.
- KMS wraps DEK with tenant master key.
- SDK encrypts payload locally using DEK.
- Gateway unwraps DEK on-demand for prompt decryption only.

### 3) Rotation
- Tenant master key versions incremented.
- New DEKs are wrapped with latest TMK version.
- Existing payloads can be rewrapped or re-encrypted based on policy.

### 4) Revocation
- Tenant key version revoked and blocked.
- Decrypt requests referencing revoked versions are denied and logged.

### 5) Destruction
- Root key destruction invalidates all tenant keys.
- TMK destruction invalidates all DEKs for tenant.

## Crypto Agility
- Algorithm choices stored in policy metadata.
- Payload metadata includes algorithm identifiers and key version.
- New policies apply to new keys and rewrap operations.
