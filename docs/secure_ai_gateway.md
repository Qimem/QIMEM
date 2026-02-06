# Secure AI Gateway

## Responsibilities
- Accept encrypted prompts and wrapped DEKs.
- Decrypt in volatile memory only.
- Forward plaintext to AI providers.
- Zeroize memory buffers immediately after use.
- Emit decrypt audit logs.

## Security Controls
- Signed request validation (nonce + TTL).
- Short-lived tokens scoped to tenant.
- Strict tenant-bound policy enforcement.
- No plaintext logging.

## Future Hardening
- Enclave execution (Nitro Enclave or equivalent).
- Attestation-backed policy enforcement.
