# Rust Build Health (PyO3 + C-linked crates)

```toml
# Cargo.toml
[lib]
# Keep rlib for smooth `cargo build` / `cargo test` in Rust workflows.
# (cdylib can be split into dedicated Python packaging flow if needed.)
crate-type = ["rlib"]

[dependencies]
# Use ABI3 for stable Python ABI selection without tying runtime builds to a specific local Python build.
pyo3 = { version = "0.22.6", features = ["abi3-py38"] }
```

```toml
# .cargo/config.toml
[env]
# Pin the Python executable used by PyO3 build discovery.
PYO3_PYTHON = "python3.12"

# Force position independent code for any C/C++ code compiled by transitive build scripts.
# This avoids R_X86_64_PC32 relocation failures when shared/native code is present.
CFLAGS = "-fPIC"
CXXFLAGS = "-fPIC"

[target.x86_64-unknown-linux-gnu]
# Prefer GNU bfd linker for Linux dev/CI to avoid rust-lld PIC relocation pitfalls.
rustflags = ["-C", "link-arg=-fuse-ld=bfd"]
```

```rust
// build.rs
fn main() {
    // Configure PyO3 cfg flags for the selected Python interpreter.
    pyo3_build_config::use_pyo3_cfgs();
}
```

```bash
#!/usr/bin/env bash
# scripts/rust-dev-check.sh
# 1) Auto-fix unused imports and other fixable lints.
cargo fix --all-targets --allow-dirty --allow-staged

# 2) Build + test with PIC-safe settings.
export CFLAGS="${CFLAGS:--fPIC}"
export CXXFLAGS="${CXXFLAGS:--fPIC}"
cargo build --all-targets
cargo test --all-targets -- --nocapture

# 3) CI guardrail for unused imports.
cargo clippy --all-targets -- -D unused-imports
```
