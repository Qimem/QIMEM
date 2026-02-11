# QIMEM Unified Cryptographic Trust Platform

QIMEM is organized as a unified trust layer for AI, APIs, and distributed systems with strict separation of local cryptographic operations and tenant-scoped infrastructure controls.

## Architecture

- **QIMEM-Core** (`qimem-core/`)
  - Local/edge/CLI/WASM cryptographic engine.
  - Envelope encryption, signing, verification, and hybrid PQ session derivation.
  - Offline-capable and root-key independent.
- **QIMEM-Infra** (`qimem-infra/` + existing server in `src/server/`)
  - Multi-tenant KMS and Secure AI Gateway.
  - Root key in memory only, versioned master keys, hash-chained audit logs.
  - JWT + `X-Tenant-ID` enforcement and constant-time tenant checks.
- **Shared Cryptographic Primitives** (`qimem-crypto/`)
  - AES-256-GCM, X25519, Kyber, HKDF-SHA256, SHA-256, Ed25519, constant-time compare, zeroizing wrappers.
- **Unified SDK** (`sdk/`)
  - Browser + Node support with first-class `encrypt/decrypt/sign/verify/pqSession/wrapDek/unwrapDek/gatewayProxy`.
- **Web Control Plane + Public Playground** (`web/`)
  - Public cryptography playground and operator-focused security control plane.

## Directory Structure

```text
QIMEM/
├── qimem-crypto/                # Shared cryptographic primitives crate
├── qimem-core/                  # Local engine crate (lib + CLI + WASM hooks)
├── qimem-infra/                 # Infra interfaces (provider trait + gateway skeleton)
├── src/                         # Existing infra API/KMS/gateway implementation
├── tests/                       # Integration tests (tenant isolation, rotation, PQ, audit)
├── sdk/                         # @qimem/sdk package
├── web/                         # Next.js App Router control plane + playground
├── docs/
│   ├── api.md
│   ├── root-key.md
│   ├── schema.sql
│   ├── threat-model.md
│   └── web.md
└── examples/
```

## Infra Security Defaults

- Root key required on startup (`QIMEM_ROOT_KEY_B64` via configured source).
- Root key never persisted.
- Destructive root rotation guarded by:
  - `ENABLE_DESTRUCTIVE_ROTATION=true`
  - `QIMEM_ROOT_ROTATION_CONFIRMATION=CONFIRM_ROOT_ROTATION_AND_DATA_REENCRYPTION`
  - `--dry-run` preflight.
- Legacy `/v0` endpoints are deprecated and should be disabled in production policy.

## Integration Test Coverage

The integration suite covers:

- Encrypt → rotate master key → decrypt continuity.
- Cross-tenant isolation rejection.
- Hybrid PQ session derivation metadata correctness.
- Audit hash-chain integrity.
- Root rotation dry-run/flag enforcement and execution behavior.

Run:

```bash
cargo test
```

## SDK Quick Start

```ts
import { init, encrypt, decrypt, gatewayProxy } from "@qimem/sdk";

const client = init({
  apiKey: "<jwt>",
  tenantId: "<tenant-id>",
  baseUrl: "http://localhost:8080",
});

const blob = await encrypt(client, "hello qimem");
const text = await decrypt(client, blob);
const response = await gatewayProxy(client, blob, { provider: "mock" });
```

## Threat Model

See `docs/threat-model.md` for adversary assumptions, HNDL posture, tenant isolation guarantees, root-key compromise impact, gateway plaintext exposure boundaries, and audit tamper detection model.
