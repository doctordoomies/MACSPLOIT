# Development

This checkout currently contains repository infrastructure and design documents.
Application build commands will be added only after they work on the first
SwiftUI/Rust slice. No scanner installation or live assessment is needed now.

## Local setup

Requirements: Git, Python 3.10+, and authenticated GitHub CLI access for pushes.

```sh
./scripts/setup-hooks.sh
python3 -m unittest discover -s tests -v
python3 scripts/check_repository.py --all-history
```

The setup script changes only this clone's `core.hooksPath`; it refuses to
replace a different configured hooks directory or existing executable native
hooks without review. Run it again after cloning. It does not install software.

## Working changes

Keep commits focused, with messages that explain the change. Stage intended
files explicitly and inspect `git diff --cached`. Run
`python3 scripts/check_repository.py --staged` before committing and inspect
the complete outgoing history before pushing. The installed hooks repeat the
audit automatically. Failures must be fixed, never bypassed.

Keep credentials in Keychain and runtime data outside the checkout. All `.env`
files are ignored, including examples; document environment variable names in
Markdown instead. Do not force-add ignored data. Dependency lockfiles belong in
Git when build manifests are introduced; build products and local databases do
not.

## First application slice

1. Research and record the Swift/Rust bridge and macOS execution constraints.
2. Add the Rust workspace, SwiftUI app, versioned contract, and build commands.
3. Add workspace creation and SQLite migration version 1.
4. Register a deterministic offline provider through the real provider interface.
5. Persist discoveries and events; display the asset graph and inspector.
6. Verify restart, cancellation, scope, provenance, and deduplication behavior.
7. Build and launch the macOS application, then record verified requirements.

Use unit tests for target classification, normalization, graph invariants, scope,
and correlation; migration tests for storage; fixture tests for parsers; and
integration tests for Recon Chains. Tests must not scan public infrastructure.
Keep incomplete functionality explicitly marked and avoid broad fake subsystems.
