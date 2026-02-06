# SDK Interface Specification

## Shared Concepts
- **Tenant Context**: `tenant_id`, policy, key version.
- **Hybrid Key Exchange**: X25519 + Kyber1024.
- **Envelope Encryption**: DEK wrapped by KMS, payload encrypted locally.

## JavaScript SDK (Browser + Node)

```ts
const client = await Qimem.initialize({
  tenantId,
  kmsBaseUrl,
  tokenProvider,
  policy: {
    deterministicEncryption: false,
  },
});

const { ciphertext, wrappedDek, metadata } = await client.encrypt({
  plaintext,
  context: "prompt",
});

const response = await client.gateway.invoke({
  provider: "openai",
  ciphertext,
  wrappedDek,
  metadata,
});
```

**Key APIs**
- `initialize(config)`
- `encrypt({ plaintext, context })`
- `decrypt({ ciphertext, wrappedDek, metadata })`
- `wrapKey({ dek })`
- `gateway.invoke({ provider, ciphertext, wrappedDek })`

## Python SDK

```python
client = QimemClient(
    tenant_id=tenant_id,
    kms_base_url=kms_base_url,
    token_provider=token_provider,
    policy={"deterministic_encryption": False},
)

payload = client.encrypt(
    plaintext=b"Sensitive prompt",
    context="prompt",
)

response = client.gateway.invoke(
    provider="openai",
    ciphertext=payload.ciphertext,
    wrapped_dek=payload.wrapped_dek,
    metadata=payload.metadata,
)
```

**Key APIs**
- `encrypt(plaintext, context)`
- `decrypt(ciphertext, wrapped_dek, metadata)`
- `wrap_key(dek)`
- `gateway.invoke(provider, ciphertext, wrapped_dek, metadata)`

## Deterministic Encryption (Vector Search)
- Explicit opt-in per tenant policy.
- Deterministic mode uses fixed-nonce or SIV-style AEAD.
- Metadata records deterministic flag for audit.
