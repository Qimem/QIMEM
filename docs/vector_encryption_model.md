# Encrypted Vector Database Integration

## Goals
- Protect original documents end-to-end.
- Enable similarity search while minimizing exposure.

## Data Flow
1. Client encrypts source documents using DEK.
2. Embeddings generated either on-device or within secure gateway.
3. Store:
   - Encrypted documents (always encrypted).
   - Embeddings stored as plaintext or deterministically encrypted based on policy.

## Encryption Modes

### Standard Mode (Preferred)
- Documents encrypted with random-nonce AEAD.
- Embeddings stored in plaintext for accurate similarity search.
- Exposure: embeddings may leak semantic information.

### Deterministic Mode
- Embeddings encrypted deterministically for equality-style lookup.
- Tradeoff: reduces semantic security and can leak structure.
- Useful for exact-match or filtered searches, not full ANN similarity.

## Threat Model Notes
- Embeddings can leak sensitive attributes through model inversion.
- Use deterministic encryption only with explicit tenant opt-in.
- Consider per-tenant embedding encryption keys to limit cross-tenant leakage.

## What Is Encrypted vs Exposed
- **Encrypted**: source documents, raw prompts, API keys, DEKs, TMKs.
- **Optionally Encrypted**: embeddings.
- **Exposed**: vector index metadata, access patterns (unless private compute used).
