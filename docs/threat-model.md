# QIMEM Threat Model

## Adversary Assumptions
- Network adversary can observe, replay, and tamper with packets.
- Tenant-level adversary can obtain valid JWT for their own tenant and attempts cross-tenant data access.
- Compromised operator workstation can invoke management APIs but cannot extract server memory from hardened production nodes.
- Cloud persistence systems (Postgres, object storage, logs) are considered recoverable by an attacker.

## Harvest-Now-Decrypt-Later
QIMEM mitigates HNDL by deriving hybrid session keys from X25519 + Kyber KEM and HKDF-SHA256 context binding. Captured ciphertext remains protected if one primitive degrades, as long as the paired primitive remains secure.

## Tenant Isolation Guarantees
- All `/v1/*` cryptographic routes require JWT claims and `X-Tenant-ID`.
- Tenant comparisons are performed in constant-time to reduce oracle leakage.
- Wrapped DEKs and key material are scoped by tenant ID and key version.

## Root Key Compromise Scenario
If the root key is compromised, attacker can unwrap tenant master keys and historical DEKs. Controls:
- Root key is memory-only and never persisted.
- Startup fails closed when root key is missing.
- Destructive root rotation rewraps every tenant master key version with explicit confirmation and dry-run gate.

## Gateway Plaintext Exposure Window
Gateway decrypts request payload in memory immediately before provider forwarding. Plaintext exists only during request handling and is zeroized after provider response assembly. Gateway responses and logs must avoid plaintext serialization.

## Audit Tampering Detection
Audit records are hash-chained (`prev_hash -> event_hash`). Any insert/delete/reorder mutates downstream hashes and is detectable during chain verification. Regular verification jobs should alert on first mismatch index.
