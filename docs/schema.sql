CREATE TABLE tenants (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  wrapped_master_key BYTEA NOT NULL,
  -- BIGINT aligns with Rust-side i64 DB bindings to avoid INT4/INT8 decode mismatch.
  key_version BIGINT NOT NULL DEFAULT 1,
  crypto_policy_version BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL
);

CREATE TABLE tenant_master_key_versions (
  tenant_id UUID REFERENCES tenants(id),
  -- Version counters are BIGINT for consistent Rust i64 compatibility.
  version BIGINT NOT NULL,
  wrapped_master_key BYTEA NOT NULL,
  created_at TIMESTAMP NOT NULL,
  PRIMARY KEY (tenant_id, version)
);

CREATE TABLE tenant_pq_keys (
  tenant_id UUID REFERENCES tenants(id),
  algorithm TEXT NOT NULL,
  public_key BYTEA NOT NULL,
  wrapped_private_key BYTEA NOT NULL,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE audit_logs (
  id UUID PRIMARY KEY,
  tenant_id UUID REFERENCES tenants(id),
  event_type TEXT NOT NULL,
  event_hash BYTEA NOT NULL,
  prev_hash BYTEA,
  metadata JSONB,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE root_key_rotations (
  id UUID PRIMARY KEY,
  started_at TIMESTAMP NOT NULL,
  completed_at TIMESTAMP,
  -- Counters are BIGINT to match i64 across SQLx decode paths.
  tenant_count BIGINT NOT NULL,
  dry_run BOOLEAN NOT NULL
);
