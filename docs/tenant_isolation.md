# Tenant Isolation Specification

## Tenant Object
```
Tenant {
  id
  wrapped_master_key
  key_version
  pq_keypair
  policies
  audit_chain_root
}
```

## Isolation Principles
- Every operation requires `tenant_id` and is scoped by JWT claims.
- Tenant master keys are unique per tenant and versioned.
- No shared key material between tenants.
- Audit logs and vault data are partitioned per tenant.

## API Enforcement
- JWT must include `tenant_id` and `scope` claims.
- KMS checks tenant ID on every request (including unwrap and policy reads).
- Gateway requests must carry a signed token bound to tenant and TTL.

## Data Enforcement
- Database partitioning by tenant (tenant_id as primary partition key).
- Row-level access enforcement at query layer.
- Encryption metadata always includes tenant_id and key_version.

## Key Boundaries
- Root key is environment-scoped; never tenant-scoped.
- Tenant master key wraps DEKs only for the same tenant.
- DEKs never cross tenant boundaries.

## Failure Behavior
- Any tenant mismatch results in a hard deny and audit log entry.
- No partial success: key unwrap is all-or-nothing.
