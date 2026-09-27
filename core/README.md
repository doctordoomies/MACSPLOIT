# Rust core

**IMPLEMENTED:** one Cargo crate with a library and `macsploit-core` helper.
Modules own assets, targets, scope, migrations/storage, evidence, events,
providers, orchestration, and the versioned internal protocol. The only registered
provider is synthetic and performs no network or subprocess work.

From the repository root, `scripts/build-core.sh` builds the helper and
`scripts/test.sh` runs all layers. Rust-only: `cargo test --locked --workspace`.
See [architecture](../docs/architecture.md) and [development](../docs/development.md).
