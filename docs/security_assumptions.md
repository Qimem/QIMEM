# Security Assumptions & Limitations

## Assumptions
- Clients securely store their credentials and do not leak JWTs.
- Cloud KMS/HSM is trusted for root key protection.
- SDK integrations follow recommended usage patterns.

## Limitations
- If client devices are compromised, data can be exposed before encryption.
- Deterministic encryption reduces semantic security; use only when necessary.
- Embedding privacy is limited by model inversion risks at providers.
- Enclave-based protections depend on platform maturity and attestation policy.
