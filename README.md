# QIMEM: End-to-End Encryption Infrastructure for AI Startups

QIMEM is a production-grade encryption platform that provides a **drop-in, end-to-end encryption layer** for AI startups handling sensitive data. It delivers per-tenant key isolation, envelope encryption, post-quantum readiness, secure prompt processing, and encrypted secret storage.

## Core Mission

- **Encrypt before AI**: User data is encrypted client-side before reaching AI providers.
- **Per-tenant isolation**: Keys are unique and isolated per tenant.
- **Zero persistent plaintext**: Servers never store plaintext keys or data.
- **Post-quantum readiness**: Hybrid key exchange (X25519 + Kyber1024).
- **Operational security**: Audit logs and policy controls built-in.

## System Architecture

QIMEM is a 3-layer system:

1. **Client SDKs** (JS + Python)
   - Encrypt locally, wrap keys, and invoke the gateway.
2. **QIMEM KMS** (Core Service)
   - Tenant provisioning, key lifecycle, policy enforcement, audit logs.
3. **Secure AI Gateway**
   - Decrypts in volatile memory only and forwards to AI providers.

Detailed specs are in `docs/`:
- Architecture: `docs/architecture.md`
- Threat model: `docs/threat_model.md`
- Tenant isolation: `docs/tenant_isolation.md`
- Cryptographic lifecycle: `docs/cryptographic_lifecycle.md`
- Key rotation: `docs/key_rotation_plan.md`
- API spec: `docs/api.md`
- SDK interface: `docs/sdk_interface.md`
- Audit schema: `docs/audit_log_schema.md`
- Deployment: `docs/deployment_model.md`
- Scaling: `docs/scaling_considerations.md`
- Security assumptions: `docs/security_assumptions.md`
- Vector DB model: `docs/vector_encryption_model.md`
- API key vault: `docs/api_key_vault.md`
- Post-quantum strategy: `docs/post_quantum_strategy.md`

## Repository Layout

```
qimem/
├─ src/                # Rust core, API server, crypto modules
├─ web/                # Web console
├─ python/             # Python tests (CLI bindings)
├─ docs/               # Architecture and security specs
└─ .env.example        # API configuration template
```

## Running the API (Development)

1. Copy and configure `.env.example`.
2. Run the API server:

```bash
cargo run --bin qimem-api
```

### Environment Variables

- `QIMEM_AUTH_DISABLED` — set to `true` for local development.
- `BETTER_AUTH_JWT_SECRET` — JWT signing secret.
- `BETTER_AUTH_ISSUER` / `BETTER_AUTH_AUDIENCE` — JWT validation controls.
- `QIMEM_ALLOWED_COUNTRIES` — Optional allow-list.
- `QIMEM_REQUIRE_MFA` — Require MFA on requests.

## Web Console

The web console is a **Security Control Plane** for tenant management, key lifecycle, policy configuration, and audit inspection.

```bash
cp web/.env.example web/.env.local
npm run web:install
npm run web:dev
```

## License

Copyright © QIMEM. All rights reserved.
