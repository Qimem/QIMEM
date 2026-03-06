# QIMEM Platform — Encryption + QAuth Identity

## What it is
QIMEM is a unified security platform delivering deterministic encryption/key lifecycle management and a built-in QAuth identity service with JWT issuance, RBAC, MFA (TOTP), token refresh/revocation, and plugin registration APIs.

## What it is not
QIMEM now exposes `/v1/security/*`, `/v1/auth/*`, and `/v1/plugins/*` versioned APIs from the `qauth-api` binary.

## Architecture
- `qimem` library: crypto engine, envelope format, key store traits, in-memory store, optional Postgres store (`stateful` feature).
- `qimem-api` binary: Axum HTTP API for key lifecycle and encryption operations.
- `qimem` binary: CLI for key generation, encryption, decryption, and rotation.

## Envelope spec
Envelope v1 fields:
- `version: u8`
- `algorithm: Algorithm`
- `key_id: Uuid`
- `nonce: Vec<u8>`
- `ciphertext: Vec<u8>`
- `tag: Vec<u8>`

Serialization:
- Deterministic binary format via `serialize_binary` / `deserialize_binary`
- Deterministic JSON format via `serialize_json` / `deserialize_json`

Validation:
- Version must be `1`
- Algorithm ID must be known
- Tampered payloads fail with structured decryption errors

## Key rotation design
- Rotation creates a new active key record and deactivates the old key.
- Old keys remain available for decrypt compatibility.
- Inactive keys are rejected for encryption.

## Running locally
```bash
cp .env.example .env
cargo run --bin qimem-api
```

## Running with Docker
```bash
docker compose up --build
curl -fsS http://localhost:8080/health
```

## API quickstart (curl)
```bash
# Create key
KEY_ID=$(curl -fsS -X POST http://localhost:8080/keys \
  -H 'content-type: application/json' \
  -d '{}' | jq -r '.key_id')
# Response shape: {"key_id":"<uuid>"}

# Encrypt (request field is `input`)
ENVELOPE=$(curl -fsS -X POST http://localhost:8080/encrypt \
  -H 'content-type: application/json' \
  -d "{\"key_id\":\"${KEY_ID}\",\"input\":\"hello\"}" | jq -r '.envelope')

# Decrypt
curl -fsS -X POST http://localhost:8080/decrypt \
  -H 'content-type: application/json' \
  -d "{\"input\":\"${ENVELOPE}\"}"
# Response shape: {"plaintext":"hello"}
```

## Production considerations
- Key material is wrapped with `zeroize::Zeroizing`.
- No key bytes are logged.
- `#![deny(missing_docs)]` and `#![deny(unsafe_code)]` are enabled.
- Use `stateful` mode with managed Postgres and encrypted disks.


## Unified platform server
```bash
cargo run --bin qauth-api
```

## QAuth CLI
```bash
cargo run --bin qauth -- --help
```
