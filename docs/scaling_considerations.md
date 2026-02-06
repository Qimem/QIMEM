# Scaling Considerations

## KMS
- Stateless API nodes behind load balancer.
- Horizontal scale for wrap/unwrap throughput.
- Cache tenant policy metadata with short TTL.

## Gateway
- Autoscale on decrypt demand.
- Rate-limit per tenant and per token.
- Separate pool for high-sensitivity tenants.

## Storage
- Tenant partitioning for key metadata and audit logs.
- Use write-optimized storage for audit chains.

## Latency
- Hybrid key exchange performed once per session.
- DEK wrapping is the primary per-request KMS operation.
