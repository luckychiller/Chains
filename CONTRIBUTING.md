# Contributing to Chains

Thank you for your interest in Chains! We are in early alpha and every contribution counts.

## Getting started

1. Install Rust 1.75+ via [rustup](https://rustup.rs).
2. Clone the repo and build:
   ```sh
   cargo build
   ```
3. Run the test suite (required to pass before any PR):
   ```sh
   cargo test
   cargo clippy --all-targets -- -D warnings
   cargo fmt --check
   ```

## Ground rules

- **Tests land with features.** Any change to `src/crypto`, `src/models`, `src/storage`, or `src/network` must include tests.
- **Never roll your own crypto.** Compose the audited primitives already in the tree (`ed25519-dalek`, `chacha20poly1305`, `x25519-dalek`, `blake3`).
- **Never commit keys or databases.** `.gitignore` covers `*.key` and `*.db/` — keep it that way.

## Where to help

See [plan.md](plan.md) for the milestone roadmap and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the protocol design.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
