# QIMEM — Secure Cryptography Platform (Private Beta)

QIMEM is a **closed-source cryptography platform** built in Rust with a hardened API and a monochrome, military-grade web console. The platform exposes key derivation, encryption with self-destruct policies, signing, TOTP/MFA, and post‑quantum session establishment for modern zero‑trust environments.

> **Access policy**: QIMEM is no longer open source. Distribution is restricted and governed by private licensing.

## What QIMEM Does

- **Zero‑trust access**: Every API request is authenticated and policy‑gated.
- **Hardware‑bound key derivation**: Device fingerprints can be used to bind keys to hardware.
- **Self‑destruct encryption**: Payloads can be encrypted with expiration timestamps.
- **Post‑quantum sessions**: Kyber1024 key encapsulation for forward‑secure session bootstrapping.
- **Signing & verification**: Ed25519 signing for integrity and identity.
- **MFA (TOTP)**: Built‑in second‑factor secrets and verification.
- **Geofencing**: Optional country allow‑lists using edge‑provided headers.
- **Rate limiting**: Enforced at the API layer.

## Repository Layout

```
qimem/
├─ src/                # Rust core, API server, crypto modules
├─ web/                # Next.js web console (Vercel‑ready)
├─ python/             # Python tests (CLI bindings)
├─ docs/               # Extended references
└─ .env.example        # API configuration template
```

## Running the API

1. Copy and configure `.env.example`.
2. Run the API server:

```bash
cargo run --bin qimem-api
```

### Required Environment Variables

- `BETTER_AUTH_JWT_SECRET` — JWT signing secret from Better Auth.
- `BETTER_AUTH_ISSUER` / `BETTER_AUTH_AUDIENCE` — JWT validation controls.
- `QIMEM_ALLOWED_COUNTRIES` — Optional comma‑separated allow‑list.
- `QIMEM_REQUIRE_MFA` — `true` to require TOTP on every request.

## Running the Web Console (Vercel‑ready)

```bash
cp web/.env.example web/.env.local
npm run web:install
npm run web:dev
```

The UI is a monochrome, military‑grade control panel and expects a Better Auth JWT to be supplied by the operator.

## API Overview (JSON)

- `POST /v1/derive-key`
- `POST /v1/encrypt`
- `POST /v1/decrypt`
- `POST /v1/sign`
- `POST /v1/verify`
- `POST /v1/totp/secret`
- `POST /v1/totp/code`
- `POST /v1/totp/verify`
- `POST /v1/pq/keypair`
- `POST /v1/pq/encapsulate`
- `POST /v1/pq/decapsulate`

All endpoints require `Authorization: Bearer <token>`.

## Security Notes

- **Key derivation** uses Argon2id with strict parameters.
- **Symmetric encryption** uses ChaCha20‑Poly1305 with random nonces.
- **Post‑quantum** sessions use Kyber1024 (encapsulation/decapsulation).
- **Self‑destruct** payloads are enforced at decrypt‑time with embedded expiry.
- **Policy enforcement** can reject requests by country or missing MFA.

## License

Copyright © QIMEM. All rights reserved.
