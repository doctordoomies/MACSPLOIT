# Contributing to MACSPLOIT

Thanks for wanting to help build MACSPLOIT.

MACSPLOIT is a native macOS security workbench with a SwiftUI application and a Rust core. Contributions are welcome across UI/UX, core architecture, provider integrations, testing, documentation, and security review.

The project is security-sensitive, so the best contribution is not necessarily the biggest one. Focused, well-tested changes are strongly preferred.

## Start here

If this is your first contribution:

1. Read the [README](README.md) for the product model.
2. Read [Architecture](docs/architecture.md).
3. Read the [Security model](docs/security-model.md).
4. Look through the [open issues](https://github.com/doctordoomies/MACSPLOIT/issues).
5. Comment before starting a large architectural change.
6. Keep your PR focused.

For provider work, also read [Provider development](docs/provider-development.md).

## Ways to contribute

### Swift / SwiftUI

Good areas include:

- workbench UX;
- result presentation;
- accessibility;
- responsive layouts;
- navigation;
- provider/setup experience;
- tests around `MACSPLOITKit`.

### Rust core

Good areas include:

- persistence and migrations;
- typed protocol surfaces;
- orchestration;
- scope/risk enforcement;
- process supervision;
- parser hardening;
- evidence/provenance;
- offline integration tests.

### Providers

Providers can be external CLI integrations or native capabilities.

A provider contribution should make it clear:

- what capability it provides;
- what target/asset types it accepts;
- its risk class;
- how scope is enforced;
- how execution is bounded;
- what machine-readable output is parsed;
- what normalized assets/relationships/observations it produces;
- how Evidence is preserved;
- how it is tested without touching the internet.

### Documentation

Documentation improvements are valuable.

Useful contributions include:

- diagrams;
- screenshots;
- provider setup troubleshooting;
- local-app tutorials;
- architecture explanations;
- migration notes;
- contributor onboarding.

### Security review

MACSPLOIT benefits from adversarial review of its own boundaries.

Useful review areas include:

- scope expansion;
- path handling;
- provider output parsing;
- process cancellation;
- installer/download verification;
- evidence redaction;
- protocol validation;
- database migrations;
- UI claims that do not match core behavior.

For an undisclosed vulnerability in MACSPLOIT itself, use [Private Vulnerability Reporting](https://github.com/doctordoomies/MACSPLOIT/security/advisories/new) instead of a public issue.

## Ground rules

### Authorized use only

Do not contribute features whose primary purpose is unauthorized access, credential theft, persistence, covert surveillance, or automatic exploitation against third-party systems.

### Automated tests stay offline

Tests must never scan the public internet or depend on live DNS.

Use:

- fake executables under `fixtures/`;
- static JSON/XML/text fixtures;
- synthetic targets;
- documentation IP ranges;
- injectable/static DNS behavior;
- local deterministic servers where the test harness explicitly owns them.

### Never commit real assessment data

Do not put real client/target information, credentials, tokens, captured evidence, or private assessment material in:

- source code;
- fixtures;
- screenshots;
- issues;
- pull requests;
- commit messages.

### Treat provider output as hostile

Provider output is untrusted input.

Bound:

- runtime;
- stdout/stderr size;
- record count;
- line length;
- redirect behavior;
- parser memory use.

Validate fields before normalization.

A malformed provider response must not crash the workbench.

### No shell command construction

External tools must run through the process supervisor using an executable plus argument array.

Do not introduce `/bin/sh -c`, string-built shell commands, `curl | sh`, or equivalent execution paths.

### Scope remains authoritative

Do not widen scope implicitly.

Active providers must evaluate the exact asset they are about to use against workspace authorization and risk policy.

## Development setup

### Requirements

- macOS 13+
- Swift 6+
- stable Rust 1.90+
- Python 3.10+
- Git
- authenticated GitHub CLI when pushing

Clone and bootstrap:

```sh
git clone https://github.com/doctordoomies/MACSPLOIT.git
cd MACSPLOIT

./scripts/setup-hooks.sh
./scripts/build-core.sh
./scripts/test.sh
./scripts/build-macos.sh
```

Launch:

```sh
open build/MACSPLOIT.app
```

or during normal development:

```sh
./scripts/run.sh
```

## Repository layout

```text
apps/macos/     SwiftUI app and MACSPLOITKit
core/           Rust core
schemas/        Internal protocol
fixtures/       Offline test fixtures
tests/          Repository/integration tests
scripts/        Build/test/audit scripts
docs/           Architecture, roadmap, provider, security docs
```

## Making a change

1. Branch from the current `main`.
2. Keep the change focused.
3. Add or update tests.
4. Update docs if behavior changes.
5. Run the canonical test/audit commands.
6. Open a PR and complete the template.
7. Leave the final merge decision to the owner/maintainer.

Conventional commit examples:

```text
feat(provider): add ...
fix(core): prevent ...
fix(macos): correct ...
test(recon): cover ...
docs: explain ...
```

## Required local verification

At minimum:

```sh
./scripts/test.sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
python3 scripts/check_repository.py --reachable-history HEAD
```

Provider-specific changes may require additional targeted tests.

Do not weaken tests, policy checks, or repository audits simply to make a PR green.

## Adding a provider

A provider PR should include:

- [ ] Capability and provider identity
- [ ] Risk classification
- [ ] Supported target/asset types
- [ ] Explicit scope behavior
- [ ] Machine-readable parsing
- [ ] Bounded runtime/output/concurrency
- [ ] Executable discovery and version detection where external
- [ ] No shell invocation
- [ ] Evidence-first behavior
- [ ] Normalized assets/relationships/observations
- [ ] Offline fixtures and malformed-output tests
- [ ] Documentation updates
- [ ] Feature-matrix update when status changes

Do not mark a provider or feature `STABLE` simply because it works once. Status should match the project's documented Definition of Done.

## Roadmap discipline

MACSPLOIT has one active product milestone at a time.

The canonical order lives in [docs/roadmap.md](docs/roadmap.md).

New ideas are welcome, but an issue being opened does not automatically move it ahead of the active milestone. This keeps the project from becoming a collection of partially integrated tools.

If your proposal belongs to a later milestone, it can still be discussed and designed without being implemented immediately.

## Pull requests

Open PRs against `main`.

The PR should explain:

- what changed;
- why it changed;
- related issues;
- security/scope implications;
- tests performed;
- documentation changes.

CI must pass.

A maintainer will review correctness, security boundaries, scope/risk implications, and roadmap fit.

By contributing, you agree that your contributions are licensed under the project's [Apache License 2.0](LICENSE).
