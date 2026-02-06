CREATE TABLE tenants (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  wrapped_master_key BYTEA NOT NULL,
  key_version INT NOT NULL DEFAULT 1,
  crypto_policy_version INT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);

CREATE TABLE tenant_pq_keys (
  tenant_id UUID REFERENCES tenants(id),
  public_key BYTEA NOT NULL,
  wrapped_private_key BYTEA NOT NULL,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE audit_logs (
  id UUID PRIMARY KEY,
  tenant_id UUID,
  event_type TEXT,
  event_hash BYTEA,
  prev_hash BYTEA,
  metadata JSONB,
  created_at TIMESTAMP
);
