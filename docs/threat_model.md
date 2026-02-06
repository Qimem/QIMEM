# Threat Model

## Assets
- Tenant master keys (TMKs).
- Data encryption keys (DEKs).
- Encrypted prompts, responses, documents, embeddings.
- API keys stored in the vault.
- Audit logs and integrity chains.
- Tenant identity and policy metadata.

## Actors
- External attackers (network, supply chain, malicious users).
- Malicious tenant admins or compromised client apps.
- Insider threats with access to infrastructure.
- Cloud provider threats (hypervisor escape, snapshot leakage).

## Trust Boundaries
- Client environments (SDKs) are untrusted; they must not receive other tenants' keys.
- KMS is trusted for key operations but cannot store plaintext keys.
- Gateway is trusted to decrypt in memory but must not persist plaintext.
- Storage systems are untrusted; all sensitive materials must remain encrypted.

## Threats & Mitigations

### Cross-Tenant Key Exposure
**Threat**: Tenant A gains access to Tenant B keys.
**Mitigations**
- Every key operation requires tenant_id + policy bound JWT scope.
- Tenant-scoped key material; no shared keys.
- DB-level row-level filtering and tenant partitioning.

### Key Exfiltration
**Threat**: Root key or TMK leakage leads to broad compromise.
**Mitigations**
- Root key stored in HSM/KMS (cloud) and never persisted in plaintext.
- TMKs encrypted at rest, rotated, and versioned.
- Short-lived access tokens for unwrap operations.

### Unauthorized Decrypt
**Threat**: Decrypt requests executed without valid authorization.
**Mitigations**
- Signed request validation with nonce and TTL.
- JWT with tenant scope and policy checks.
- Explicit audit log entry on every decrypt attempt.

### Prompt Leakage
**Threat**: Prompt or response is leaked at the gateway.
**Mitigations**
- Decrypt only in volatile memory; zeroize buffers.
- Minimize logging; never log plaintext.
- Option for enclave-based deployment.

### Embedding Leakage
**Threat**: Embeddings leak sensitive data or allow reconstruction.
**Mitigations**
- Option to encrypt embeddings deterministically.
- Documentation of search vs. privacy tradeoffs.
- Tenant policy to enforce embedding encryption.

### Replay Attacks
**Threat**: Attacker replays signed requests.
**Mitigations**
- Nonce + TTL in signed requests.
- Audit log tracking and invalidation of used nonces.

### Audit Log Tampering
**Threat**: Attacker modifies logs to hide misuse.
**Mitigations**
- Hash-chained log entries with periodic root anchors.
- Write-once storage option.
- Integrity verification tooling.

## Out of Scope
- Client device compromise beyond SDK protections.
- Physical attacks on end-user devices.
- ML model inversion attacks at third-party AI providers.
