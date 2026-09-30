# Contributing to MACSPLOIT

Thanks for your interest in contributing! MACSPLOIT is a native macOS security
workbench built around a **provider architecture**, and new providers are the most
valuable contributions. Please read this guide and the
[provider development guide](docs/provider-development.md) before opening a PR.

## Ground rules (security tool)

- **Authorized use only.** Do not contribute features whose primary purpose is
  unauthorized access, credential theft, persistence, covert surveillance, or
  automatic exploitation.
- **Offline tests only.** Automated tests must never scan the internet or perform
  real DNS. Use the fake executables (`fixtures/fake-*.sh`), XML/JSON fixtures, and
  the injectable static DNS resolver.
- **No real target data or secrets** in code, tests, fixtures, commits, or issues.
- **Provider output is hostile.** Treat all external tool output as untrusted:
  bound size, line length, record count, and runtime; validate fields; never let one
  malformed record crash a run.
- **No shells.** Execute tools via the process supervisor with an argument array,
  never `/bin/sh -c`.
- **Respect scope and risk classes.** Active providers must only run against
  in-scope assets; never widen scope.

## Development setup

Prerequisites: macOS 13+, Swift 6+ (Xcode or Command Line Tools), Rust (stable),
Python 3.10+, and (for pushing) an authenticated GitHub CLI.

```sh
git clone https://github.com/doctordoomies/MACSPLOIT.git
cd MACSPLOIT
./scripts/setup-hooks.sh    # local commit/push safety hooks (recommended)
./scripts/build-core.sh
./scripts/test.sh           # Rust + Swift + repository-policy tests
./scripts/build-macos.sh
```

Repository layout, the Swift↔Rust bridge, database migrations, the provider trait,
risk classes, scope checks, evidence format, and the testing strategy are documented
under [docs/](docs/) — especially [architecture](docs/architecture.md),
[providers](docs/providers.md), and [development](docs/development.md).

## Making changes

- Keep `main` stable; branch for your change.
- Use focused, conventional commits (`feat(provider): …`, `fix(core): …`,
  `test(...): …`, `docs: …`).
- Run the full suite before pushing: `./scripts/test.sh`.
- Rust: keep it warning-clean and `cargo fmt`-formatted; run `cargo clippy`.
- Update documentation and the [feature matrix](docs/features.md) when behavior or
  status changes. Do not mark something IMPLEMENTED/STABLE unless it truly is.

## Adding a provider (checklist)

A provider PR should include:

- [ ] Risk classification, target types, and capabilities
- [ ] Scope behavior (and per-asset scope where the provider is active)
- [ ] Machine-readable parsing (never scraping human/terminal output)
- [ ] Bounded execution (timeout, output size, concurrency) via the supervisor
- [ ] Executable discovery + installation/version detection (no silent installs)
- [ ] Offline fixtures / a fake executable, plus malformed-output tests
- [ ] Evidence-first behavior (raw output preserved and hashed before parsing)
- [ ] Docs updates (providers.md, recon-chain.md if a stage is added, features.md)

## Pull requests

Open a PR against `main` and fill out the PR template. CI (Rust build/test/clippy,
Swift tests, repository-policy tests, offline integration) must pass. A maintainer
will review for correctness, security boundaries, and scope/risk implications.

By contributing, you agree that your contributions are licensed under the project's
[Apache License 2.0](LICENSE).
