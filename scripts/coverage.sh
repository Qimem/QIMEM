#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "cargo-llvm-cov is required. Install with: cargo install cargo-llvm-cov"
  exit 1
fi

cargo llvm-cov --workspace --lcov --output-path target/lcov.info
echo "Coverage report written to target/lcov.info"
