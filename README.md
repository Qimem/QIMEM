# QIMEM: Tenant-Scoped KMS + Secure AI Gateway

QIMEM is a Rust-based, tenant-scoped key management service (KMS) with strict envelope
encryption, audit chaining, and a provider-agnostic secure gateway for AI workloads. The
web console is a security control plane for operators and developers.

> **Status**: Work-in-progress. Production hardening is in progress.

## What QIMEM Does

- **Tenant-scoped KMS** with JWT + `X-Tenant-ID` enforcement.
- **Envelope encryption**: root key → tenant master key → DEK → payload.
- **Master key rotation** with versioning and audit logs.
- **Hybrid post-quantum sessions** (X25519 + Kyber + HKDF).
- **Secure AI gateway** that decrypts in memory and forwards to providers.
- **Hash-chained audit logs** for decrypts and rotations.

## Repository Layout

```
qimem/
├─ src/                # Rust core, API server, gateway, crypto modules
├─ web/                # Next.js control plane UI
├─ sdk/                # Minimal JS SDK (@qimem/sdk)
├─ examples/           # SDK examples
├─ docs/               # Architecture references
└─ tests/              # Integration test suite
```

## Running the API

1. Configure environment variables (see below).
2. Run the API server:

```bash
cargo run --bin qimem-api
```

### Required Environment Variables

- `QIMEM_DATABASE_URL` — Postgres connection string.
- `QIMEM_ROOT_KEY_SOURCE` — `env` or `secret-manager`.
- `QIMEM_ROOT_KEY_B64` — base64-encoded 32-byte root key (required for `env`).
- `BETTER_AUTH_JWT_SECRET` — JWT signing secret.
- `BETTER_AUTH_ISSUER` / `BETTER_AUTH_AUDIENCE` — optional JWT validation controls.

### Root Key Notes

- The root key **never** leaves memory and is never stored in Postgres.
- Loss of the root key is unrecoverable for encrypted data.
- Rotation is destructive and only available via the CLI (see below).

See `docs/root-key.md` for full operational guidance.

## KMS API Overview (JSON)

- `POST /v1/kms/tenants`
- `POST /v1/kms/encrypt`
- `POST /v1/kms/decrypt`
- `POST /v1/kms/wrap-dek`
- `POST /v1/kms/unwrap-dek`
- `POST /v1/kms/rotate-master-key`
- `POST /v1/kms/pq/keypair`
- `POST /v1/kms/pq/session`

Legacy demo endpoints are available under `/v0/*` and are deprecated.

## Secure Gateway

Run the gateway:

```bash
cargo run --bin qimem-gateway
```

Gateway endpoint:

- `POST /v1/gateway/proxy`

The gateway decrypts the request payload in memory, forwards plaintext to the provider,
and immediately zeroizes buffers. A mock provider reverses the prompt for safe demos.

## Root Key Rotation (Destructive)

Root rotation requires explicit intent and is **not** exposed via HTTP.

```bash
export ENABLE_DESTRUCTIVE_ROTATION=true
export QIMEM_ROOT_ROTATION_CONFIRMATION=CONFIRM_ROOT_ROTATION_AND_DATA_REENCRYPTION
export QIMEM_NEW_ROOT_KEY_B64=<base64-32-byte-key>

cargo run --bin qimem-root-rotation -- --dry-run
cargo run --bin qimem-root-rotation
```

Rotation rewraps all tenant master key versions and writes audit entries before and after.

## SDK (JavaScript)

Minimal usage:

```ts
import { Qimem } from "@qimem/sdk";

const client = new Qimem({
  apiKey: "<jwt>",
  tenantId: "<uuid>",
  baseUrl: "http://localhost:8080",
});

const encrypted = await client.encrypt("hello");
const decrypted = await client.decrypt(encrypted);
```

See `examples/sdk-basic/README.md` for a full working example.

## Web Control Plane

```bash
npm install
npm run web:dev
```

The UI provides a tenant dashboard, secure playground, and audit visualization.

## Testing

The test suite uses ephemeral Postgres via testcontainers.

```bash
cargo test
```

Coverage (requires `cargo-llvm-cov`):

```bash
./scripts/coverage.sh
```

## License

Copyright © QIMEM. All rights reserved.
