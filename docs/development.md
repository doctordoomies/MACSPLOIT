# Development

Status: runnable **IMPLEMENTED** offline foundation. No scanner installation is
needed. See [verification](phase-0-verification.md) for tested and blocked checks.

## Prerequisites

- macOS 13 minimum deployment target; Apple Silicon is the verified architecture.
- Apple Command Line Tools or Xcode with Swift 6 or newer.
- Rust/Cargo 1.90 or newer; the committed dependency lock requires this baseline.
- Git, Python 3.10+, and authenticated `gh` for private-destination checks/pushes.

Verified locally: macOS 26 on arm64, Swift 6.3.2, Rust 1.98.1. Full Xcode is not
installed on that machine. The scripts use SwiftPM and package the app directly.
Older supported macOS releases, Intel, and the full Xcode path need separate
verification. The local Swift Testing framework requires macOS 14 even though
the app targets 13; that test-runner constraint does not change the app target.

No script installs software or changes shell profiles. Set `MACSPLOIT_CARGO` to
an existing Cargo executable when it is not on PATH; use the toolchain's normal
CARGO_HOME/RUSTUP_HOME settings as needed. Initial dependency download requires
network access; tests and the application use only local synthetic data.

## Verified commands

From the repository root:

```sh
./scripts/setup-hooks.sh
./scripts/build-core.sh
./scripts/test.sh
./scripts/build-macos.sh
open build/MACSPLOIT.app
```

Fast development launch (build + open):

```sh
./scripts/run.sh
```

`build-core.sh` sets macOS deployment target 13 and uses the committed Cargo lock.
`swift-command.sh` keeps build/module caches beneath ignored `build/`. For tests
it locates the installed Swift Testing framework and runtime; no downloaded test
framework is needed. `test.sh` runs Rust, builds the real helper, then runs Swift
unit/integration tests, Python policy tests, and the full-history repository audit.
Swift tests use Swift Testing, not XCTest, to work with this CLT installation.

### Testing the Subfinder provider offline

Automated tests never run the real `subfinder` or touch the network. `test.sh`
exports `MACSPLOIT_SUBFINDER=$PWD/fixtures/fake-subfinder.sh`, an offline fake that
emits deterministic JSONL. The Rust `domain_recon` integration test injects the same
fixture through `ToolConfig`, and the Swift Domain Recon bridge test reads it from
the environment (forwarded to the helper by `PipeTransport`).

To exercise the real tool manually, install Subfinder yourself (for example
`brew install subfinder`; MACSPLOIT never installs it) so it is found on `PATH` or in
`/opt/homebrew/bin`, or point `MACSPLOIT_SUBFINDER` at a specific binary, then run
Domain Recon against a domain you are explicitly authorized to assess and that is in
the workspace scope. Do not run it against `example.com` or any host you do not own
or have written permission to test. If you have no authorized target, skip live
execution — the offline suite already proves the integration.

`build-macos.sh` assembles `build/MACSPLOIT.app`, bundles the helper, ad-hoc signs
both, and checks the bundle signature. This is a local development build, not a
notarized distribution or release. If an agent's execution sandbox blocks nested
SwiftPM sandboxing or Launch Services, use the environment's normal approval
mechanism; do not disable platform/repository protections.

## Synthetic walkthrough

1. Open the app and create **Test Assessment**.
2. Keep scope `example.test`, `*.example.test`, `192.0.2.0/24` (one per line).
3. Add `example.test` in the target bar. It should report `Domain`.
4. Choose **Recon**, run **Synthetic Recon**, and watch the five stages.
5. In **Assets**, expect 11 nodes and inspect their relationships and observations.
6. Open an observation's evidence or use **Evidence** to read verified JSON.
7. **Activity** shows ordered persisted events; the dashboard shows 10 relationships
   and 3 evidence records after the first full run.
8. Quit with Command-Q, reopen, and verify the same workspace, target, graph,
   provenance, evidence, and activity. Repeating recon retains asset IDs while
   adding new observations, evidence, and run records.

The automated cross-language test performs core shutdown/restart and verifies
these entities. The complete GUI walkthrough is still pending because the native
UI automation connection failed after workspace creation. Do not mark acceptance
complete without that remaining check.

Runtime data defaults to `~/Library/Application Support/MACSPLOIT/`. A developer
may pass `--data-dir` with an absolute location outside all Git checkouts. Tests
use temporary stores; production workspace data and evidence never enter fixtures.
The app only runs synthetic recon for `example.test`; other supported target
classes can be stored but have no providers yet.

## Working changes and push safety

Use small commits, explicitly stage intended files, and inspect
`git diff --cached`. Before committing, run:

```sh
python3 scripts/check_repository.py --staged
```

Before every push, run:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_repository.py --all-history
gh repo view doctordoomies/MACSPLOIT --json nameWithOwner,isPrivate,visibility
```

The last command must report the exact canonical name and PRIVATE visibility.
The pre-push hook independently enforces both and audits outgoing history. Read [repository policy](repository-policy.md). Never
bypass a failed hook, force-add runtime data, or commit credentials. `setup-hooks.sh`
changes only this clone and refuses conflicting hook installations.
