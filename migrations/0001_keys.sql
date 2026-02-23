CREATE TABLE IF NOT EXISTS keys (
    key_id UUID PRIMARY KEY,
    lineage_id UUID NOT NULL,
    version INTEGER NOT NULL,
    active BOOLEAN NOT NULL,
    material BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_keys_lineage_id ON keys(lineage_id);
