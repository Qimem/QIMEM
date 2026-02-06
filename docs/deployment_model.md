# Deployment Model (Cloud-Native)

## Services
- **KMS API**: Rust service, stateless, scalable horizontally.
- **Secure AI Gateway**: Isolated runtime with minimal logging.
- **Audit Log Service**: Append-only storage + verification tooling.
- **Vault Service**: Encrypted API key storage.
- **Policy Service**: Crypto agility and tenant policy management.

## Infrastructure
- Containerized deployments (Kubernetes or ECS).
- Root key stored in cloud HSM/KMS.
- Database with tenant partitioning.
- Private networking between KMS and gateway.

## Isolation
- Dedicated environments for enterprise tiers.
- Optional enclave-based gateway deployment.

## Observability
- Metrics: decrypt counts, gateway latency, error rates.
- Logs: structured, redacted, audit-chain integrity.
