# Qimem: A Rust-Based Crypto Powerhouse for Secure Data Handling

![Qimem Logo](https://placehold.co/800x200/png?text=QIMEM&font=roboto) 

– *The name means "spice" in Amharic*

Hey, I'm EyuKaz, the solo dev behind *Qimem*. For the past 3-4 months, I've been grinding through Rust's unforgiving compiler, endless dependency hell, and my own noob mistakes to build this crypto library and CLI. Now, I'm handing *Qimem* over to the community. It's not the next Linux (yet), but it's a solid foundation for secure key management, encryption, and more. If you're a smart dev, jump in, fix my bugs, and make it legendary. Be warned: this code's been through war, and it's got scars.

This README is your bible—extra descriptive, honest, and blunt. I won't sugarcoat the mess I made. No one should ask me questions; this doc answers everything. If it doesn't, open an issue on GitHub.

## What is Qimem? (The Vision and Reality)

I built *Qimem* as a pure-Rust cryptographic toolkit with a CLI for quick ops and Python bindings for easy integration. The vision was to create a sovereign, open-source crypto engine for Africa—fast, secure, and free from foreign dependencies like Twilio or Twilio clones. It was meant to be the backbone for Arthimetic's AI-driven tech stack, securing everything from SMS chats to market data. But honestly, it never got there. It's a functional crypto utility with key derivation, encryption, signing, TOTP, obfuscation, and data bucketing, but it's raw, buggy, and far from the "next Linux" I hyped it as.

In reality, *Qimem* is a proof-of-concept that shows what a solo dev can do with Rust and a lot of coffee. It's not military-grade yet—it's more like a backyard fortress made of sticks. But with community help, it could become something epic. The code's modular, with `q_keygen.rs` for keys, `q_core.rs` for encryption, `signing.rs` for signatures, and `main.rs` as the CLI entrypoint. Python bindings via `pyo3` make it usable in apps, but I ditched them for `subprocess` in the end because of linker nightmares.

**Tech Stack**:
- **Rust (edition 2021)**: Core language for safety and speed.
- **Crypto Libs**: `argon2` for key derivation, `chacha20poly1305` for encryption, `ed25519-dalek` for signatures, `totp-rs` for TOTP.
- **Utils**: `base64` for encoding, `serde_json` for output, `rand` for randomness, `thiserror` for errors.
- **Python Bindings**: `pyo3` for the module (if you keep it), `maturin` for building wheels.
- **Build Tools**: `prost-build` for Protocol Buffers, `protoc` for Signal/SPQR.

**What It Really Does**:
- **CLI**: Run commands like `qimem derive-key <password>` for keys, `qimem encrypt <message_b64> <key_b64>` for encryption, `qimem totp-generate` for 2FA secrets. Outputs JSON/base64 for easy parsing.
- **Python Integration**: Originally `pyo3` bindings (e.g., `qimem.derive_key("password")`), but switched to `subprocess` calls to the CLI binary for simplicity.
- **Core Features**: Secure key gen, symmetric encryption, TOTP, with base64/JSON for user-friendly output.

The vision was insane: real-time policy enforcement, zero-trust access, post-quantum E2EE with Signal, hardware-bound keys, geofencing, and self-destructing files. It could’ve been a game-changer for secure messaging or enterprise data in Africa, but I burnt out on bugs. Now, it's yours—build it into the "next Linux" if you can.

## Errors We Encountered (The Brutal Truth)

I went through absolute hell with Rust’s compiler. *Qimem* was a bug magnet, and here’s every major error we hit, why they happened, and possible solutions. Be blunt: most were my fault for noob code and bad dependency management, but Rust’s strictness didn’t help.

1. **Name Conflicts (E0255)**: Functions like `derive_key` defined multiple times in `lib.rs` (imported from modules, then redefined as `#[pyfunction]`).
   - **Why**: Rust hates duplicates in namespaces.
   - **Solution**: Use `wrap_pyfunction!` with module-qualified names (e.g., `q_keygen::derive_key`) in `lib.rs` without redefinition. Fixed by removing redundant definitions.

2. **Unresolved Imports (E0432)**: `crate::q_keygen`, `ed25519_dalek::Keypair`, etc., not found.
   - **Why**: Modules not declared in `lib.rs` or incorrect dependency versions/features (e.g., `ed25519-dalek` missing `std`).
   - **Solution**: Add `pub mod q_keygen;` in `lib.rs`, fix imports (e.g., `ed25519_dalek::Keypair`), and add features (e.g., `["std", "rand_core"]` in `Cargo.toml`). Cache clears (`rm -rf ~/.cargo/registry target`) helped.

3. **Trait Bounds (E0277)**: Types like `&[u8; 32]` not implementing `PyFunctionArgument`.
   - **Why**: `pyo3` expects convertible types (e.g., `Vec<u8>`) for Python args.
   - **Solution**: Change args to `Vec<u8>` and convert to arrays inside functions (e.g., `key.try_into().map_err(...)`).

4. **Argument Mismatches (E0061)**: Functions like `encrypt` expect 2 args but get 3 (missing Python context).
   - **Why**: `#[pyfunction]`s need `py: Python<'_>` for `pyo3` bindings.
   - **Solution**: Add `py: Python<'_>` to signatures and call with `Python::with_gil`.

5. **Linker Errors**: `linking with cc failed` with undefined references to Python C API (e.g., `_Py_Dealloc`).
   - **Why**: `pyo3` requires linking `libpython3.12.so`, but paths/features weren’t set.
   - **Solution**: Use `build.rs` to parse `python3-config --ldflags --libs` and add `-lpython3.12`. Install `python3.12-dev` for `libpython3.12.so`. Add `LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu` for runtime.

6. **Dependency Conflicts**: `spqr v1.2.0` feature mismatches (e.g., `cipher` not found).
   - **Why**: Incorrect features or outdated repo tags.
   - **Solution**: Remove invalid features, use `git rev = "HEAD"` for latest, clear cache (`rm -rf ~/.cargo/git registry`).

7. **Custom Build Failures**: `spqr` requires `protoc` for Protobufs.
   - **Why**: `prost-build` needs `protoc` binary.
   - **Solution**: Install `protobuf-compiler` and set `PROTOC=/usr/bin/protoc`.

8. **Type Errors (E0412, E0425)**: Missing `Keypair` or undefined types.
   - **Why**: Wrong imports or features in `ed25519-dalek`.
   - **Solution**: Use `ed25519_dalek::Keypair` and add `["std"]` feature.

9. **Unused Imports/Warnings**: `KeyInit`, `spqr::*`, `Value` unused.
   - **Why**: Leftover code from iterations.
   - **Solution**: Remove unused imports.

**General Why We Had So Many Errors**:
- My noob Rust skills—bad module structure, dependency mismatches, and not handling `pyo3`’s Python context.
- Dependency hell: `ed25519-dalek`, `spqr`, `pyo3` versions/features conflicting.
- Build Env: Codespaces quirks with caches, paths, and Python dev packages.

**Possible Solutions for Future**:
- Use `cargo fix` or `rust-analyzer` for auto-fixes.
- Clear cache often: `cargo clean; rm -rf ~/.cargo/registry`.
- Pin dependencies: Use `cargo lock` for reproducible builds.
- Test incrementally: Build CLI first, then Python module.

---

### *Qimem* Codebase Structure
- **src/lib.rs**: Python bindings with `pyo3` for functions/classes.
- **src/main.rs**: CLI entrypoint with commands and interactive mode.
- **src/q_keygen.rs**: Key derivation with `Argon2id`.
- **src/q_core.rs**: Encryption/decryption with `ChaCha20Poly1305`.
- **src/file_encryption.rs**: File crypto ops.
- **src/signing.rs**: Ed25519 signatures.
- **src/key_store.rs**: Secure key storage.
- **src/totp.rs**: TOTP for 2FA.
- **src/obfuscation.rs**: Decoy data and anti-debug.
- **src/bucketing.rs**: Sensitive data organization.
- **src/tests**: Rust unit tests.
- **src/utils.rs**: Helpers (empty for now).
- **python/tests/test_qimem.py**: Python tests with `pytest` and `subprocess`.

---

### Contributing to *Qimem*
Fork the repo on GitHub, branch your feature, and PR. Fix my bugs, add features, or refactor. Use `cargo test` for Rust, `pytest` for Python. Dependencies are in `Cargo.toml`. Build with `cargo build --release --target=x86_64-unknown-linux-gnu`. Install Python module with `maturin develop`.

---

### Contact
I’m EyuKaz on GitHub. Open issues or PRs for questions. No DMs. let the community build this.

That's *Qimem* in all its glory and gory. 
