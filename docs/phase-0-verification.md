# Phase 0 verification

Verified on 2026-09-27, Apple Silicon macOS 26, Swift 6.3.2 Command Line Tools,
Rust 1.98.1. The repository remains private; no real scanners or targets were used.

## Automated results

| Suite | Passed | Scope |
| --- | ---: | --- |
| Rust unit tests | 20 | Classification, normalization, migrations, persistence, replay, scope, provider metadata/parser, hashing, protocol, task states |
| Rust integration tests | 8 | Full graph and restart, repeat-run provenance, scoped dispatch, tamper/path checks, rollback, cancellation, isolation/lock, interruption recovery |
| Swift unit tests | 7 | Typed requests/results/errors, protocol identity, snapshot decoding, view-model restore/poll/error state |
| Swift integration tests | 1 | Actual pipe helper, SQLite, provider execution, live running state, 11 assets/10 relationships, 3 evidence records, replay, shutdown/restart equality |
| Repository policy tests | 15 | Secrets/history/index/ignore checks, canonical private destination, former-owner rejection |

Total: **51 passing tests, no failures or skipped tests** in `scripts/test.sh`.
Rust total: **28**. Swift total: **8**. Integration subtotal: **9**, already included
in the Rust/Swift totals; do not add it again.

### Independent re-verification (2026-09-27, second session)

A follow-up session re-ran the full suite and confirmed the results below. The
Rust toolchain was initially absent and was installed via rustup (stable) during
the session; before that, the previously compiled `target/debug/macsploit-core`
binary was also driven directly over the v1 stdin/stdout protocol as an
independent cross-check.

| Check | Result | Detail |
| --- | --- | --- |
| Core vertical slice + restart (direct binary drive) | PASS | `create_workspace` "Test Assessment" → `add_target` example.test (classified Domain) → `start_chain` → chain COMPLETED with **11 assets, 10 relationships, 3 evidence, 54 events**; `read_evidence` hash-verified. Closed the process, reopened the same `--data-dir`: all counts identical and evidence still readable. |
| Swift build | PASS | SwiftUI `MACSPLOIT` app compiles and links via `scripts/swift-command.sh`. |
| Swift tests | PASS | 8/8 across `ClientTests`, `WorkspaceModelTests`, `BridgeIntegrationTests`, including the live `testSwiftRustSQLiteProviderEventsAndRestart` bridge/SQLite/provider/restart test. |
| Repository policy tests | PASS | 15/15 (`python3 -m unittest discover -s tests`). |
| Repository all-history audit | PASS | `check_repository.py --all-history`: 78 file versions, no secrets, canonical owner `doctordoomies`. |
| Rust unit/integration tests | PASS | `cargo test --locked --workspace`: 20 unit + 8 integration = **28 passed, 0 failed** (rustup stable installed during the session). |
| On-screen GUI walkthrough (quit/reopen visual) | BLOCKED | No macOS desktop UI-automation tool available in that session; persistence proven only through the automated/core paths above, which do not substitute for the visual acceptance check. |

A focused code review in the same session found no Phase 0 defects: the only
subprocess spawn is the bundled core helper in `PipeTransport.swift`; the Rust
core issues no external commands; the `example.test` strings in SwiftUI are copy
and the create-workspace scope prefill, not hardcoded graph results; and there
are no `TODO`/`unimplemented!`/`fatalError`/placeholder markers in the sources.

The Rust integration scenario compares all ten expected graph edges, not just
node/edge counts. The automated Swift restart scenario closes the first helper,
opens a new helper on the same store, and compares the entire decoded snapshot:
workspace, targets, assets, relationships, observations, chains/stages/tasks,
provider runs, evidence metadata, events, and cursor. Evidence reads verify the
stored hash in Rust. These are real process/database tests, not SwiftUI previews.

## Build and launch

`scripts/build-core.sh`, `scripts/test.sh`, and `scripts/build-macos.sh` pass.
The generated native `.app` bundles the Rust helper and passes strict local
signature verification after ad-hoc signing. The app was launched and its native
sidebar, workspace creation sheet, and connected-core state were observed.
**Test Assessment** was created through the UI and independently confirmed in
its SQLite workspace outside the repository.

The Swift Testing framework installed with these CLT targets macOS 14, which
causes a test-link warning against the app's macOS 13 deployment target. Tests
pass on macOS 26. macOS 13 and Intel runtime behavior have not been verified.
The development app is not notarized or prepared for distribution.

## Remaining acceptance blocker

After the UI workspace-creation action, native UI inspection consistently failed
with `Sky Computer Use native pipe closed before response`. App inventory and
helper logs showed that MACSPLOIT remained running. A tool-session reset did not
restore native window inspection. The user instructed us to continue automated
checks and report this UI check as blocked.

Therefore **the full on-screen target → recon → inspector → evidence → quit/reopen
walkthrough remains unverified**. Automated persistence passes, but it does not
substitute for the explicitly requested GUI acceptance check. Phase 0 acceptance
remains pending that check. Follow the walkthrough in [development](development.md)
when native interaction is available, then update this report with actual results.

## Review and limitations

Staged content and complete Git history are checked by the existing repository
auditor and normal commit/push hooks. Build products, local toolchains, workspace
databases, logs, and evidence are excluded from the commit set. No safeguard was
removed or bypassed. The current owner is `doctordoomies`; the previous owner's
name is retained only as an explicit rejection fixture (and immutable history).

No real providers, external process supervisor, graph visualization, findings,
reports, tool manager, credentials, telemetry, hardware, or publishing features
are implemented. Pause/PARTIAL states are modeled but not exposed as functionality.
Full UI-quit background work, general dependency scheduling, arbitrary scanner
output redaction, retention/export, signing/notarization, and older-machine
verification remain future work. Resource limits and current lifecycle semantics
are documented in [architecture](architecture.md) and [Recon Chains](recon-chain.md).
