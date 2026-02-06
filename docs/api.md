# QIMEM KMS API Specification

## Authentication & Authorization
- JWT required for all endpoints.
- Claims: `tenant_id`, `scope`, `exp`.
- Scopes: `kms:wrap`, `kms:unwrap`, `kms:tenant:admin`, `gateway:invoke`, `vault:read`, `vault:write`.

## Core Endpoints

### POST /v1/tenants
Provision a new tenant.

**Request**
```json
{ "tenant_name": "acme" }
```

**Response**
```json
{ "tenant_id": "t_123", "key_version": 1 }
```

### GET /v1/tenants/{tenant_id}
Returns tenant metadata and active key version.

### POST /v1/keys/wrap
Wrap a DEK using the tenant master key.

**Request**
```json
{
  "tenant_id": "t_123",
  "dek_b64": "...",
  "algorithm": "chacha20poly1305",
  "key_version": 1
}
```

**Response**
```json
{
  "wrapped_dek_b64": "...",
  "key_version": 1,
  "algorithms": {
    "kem": "x25519+kyber1024",
    "kdf": "hkdf-sha256",
    "aead": "chacha20poly1305"
  }
}
```

### POST /v1/keys/unwrap
Unwrap a DEK for authorized requests.

**Request**
```json
{
  "tenant_id": "t_123",
  "wrapped_dek_b64": "...",
  "key_version": 1
}
```

### POST /v1/keys/rotate
Rotate a tenant master key.

**Request**
```json
{ "tenant_id": "t_123" }
```

### POST /v1/policies
Update tenant crypto policies.

**Request**
```json
{
  "tenant_id": "t_123",
  "crypto_policy": {
    "kem": ["x25519", "kyber1024"],
    "aead": "chacha20poly1305",
    "deterministic_encryption": false
  }
}
```

## Secure AI Gateway Endpoints

### POST /v1/gateway/token
Issue a short-lived gateway token.

**Request**
```json
{ "tenant_id": "t_123", "ttl_seconds": 60 }
```

### POST /v1/gateway/invoke
Send encrypted prompt + wrapped DEK.

**Request**
```json
{
  "tenant_id": "t_123",
  "wrapped_dek_b64": "...",
  "ciphertext_b64": "...",
  "provider": "openai",
  "request_sig": "...",
  "nonce": "..."
}
```

## Vault Endpoints

### POST /v1/vault/secret
Store encrypted API key material.

### GET /v1/vault/secret/{secret_id}
Retrieve encrypted API key material (never plaintext).

## Audit Log Endpoints

### GET /v1/audit
Returns hash-chained audit events filtered by tenant.
