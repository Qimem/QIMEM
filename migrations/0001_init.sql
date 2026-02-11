CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  wrapped_master_key BYTEA NOT NULL,
  key_version BIGINT NOT NULL DEFAULT 1,
  crypto_policy_version BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_master_key_versions (
  tenant_id UUID REFERENCES tenants(id),
  version BIGINT NOT NULL,
  wrapped_master_key BYTEA NOT NULL,
  created_at TIMESTAMP NOT NULL,
  PRIMARY KEY (tenant_id, version)
);

CREATE TABLE IF NOT EXISTS tenant_pq_keys (
  tenant_id UUID REFERENCES tenants(id),
  algorithm TEXT NOT NULL,
  public_key BYTEA NOT NULL,
  wrapped_private_key BYTEA NOT NULL,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY,
  tenant_id UUID REFERENCES tenants(id),
  event_type TEXT NOT NULL,
  event_hash BYTEA NOT NULL,
  prev_hash BYTEA,
  metadata JSONB,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS root_key_rotations (
  id UUID PRIMARY KEY,
  started_at TIMESTAMP NOT NULL,
  completed_at TIMESTAMP,
  tenant_count BIGINT NOT NULL,
  dry_run BOOLEAN NOT NULL
);
