#!/usr/bin/env bash
set -euo pipefail

# Step 1: auto-fix common hygiene issues (including unused imports) in local tree.
# NOTE: this mutates files; run before commit.
cargo fix --all-targets --allow-dirty --allow-staged

# Step 2: ensure build and tests use PIC-safe C flags + stable linker behavior.
# These are also configured in .cargo/config.toml, but we export explicitly so this script
# can be copied into CI with predictable behavior.
export CFLAGS="${CFLAGS:--fPIC}"
export CXXFLAGS="${CXXFLAGS:--fPIC}"

# Step 3: verify compile + tests.
cargo build --all-targets
cargo test --all-targets -- --nocapture

# Optional safety gate: fail on newly introduced unused imports.
# We keep this check narrow to avoid unrelated warning policies.
cargo clippy --all-targets -- -D unused-imports
