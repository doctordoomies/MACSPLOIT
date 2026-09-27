# MACSPLOIT

**Active private development.** This repository must remain private unless its
owner explicitly authorizes a visibility change. It is not a published product.

Canonical repository: [doctordoomies/MACSPLOIT](https://github.com/doctordoomies/MACSPLOIT).
The local `origin` must be `https://github.com/doctordoomies/MACSPLOIT.git`.

MACSPLOIT is a native macOS modular cybersecurity workbench for authorized
security research. Its goal is to connect targets, discoveries, findings, and
evidence in one workspace and asset graph. External tools are independent
providers; their output does not define the application's central data model.

## Current status

Repository setup is complete: monorepo boundaries, foundational design notes,
data-handling rules, and local commit/push checks. **Application implementation
has not started.** There is no runnable macOS app, Rust package, scanner
integration, or database migration yet. The documents describe planned behavior,
not features that already work.

## Planned architecture

- `apps/macos/`: SwiftUI application and native macOS navigation.
- `core/`: Rust orchestration, target classification, asset graph, provider
  supervision, events, workspace persistence, findings, and evidence references.
- `providers/`: independent adapters with capability and risk metadata.
- `schemas/`: versioned interchange contracts and schema specifications.
- `fixtures/`: synthetic, offline provider samples only.
- `tests/`: integration and repository-policy tests.
- `scripts/`: development and repository safety tooling.
- `docs/`: architecture, security, contribution guidance, and roadmap.

SQLite will store workspace state. Raw results will live in per-workspace
application storage outside Git. A Recon Chain will select work by asset type,
capability, scope, and discoveries rather than execute a fixed list of tools.

## Requirements and setup

The repository checks use Git, Python 3.10 or newer, and an authenticated GitHub
CLI (`gh`) with access to this private repository. No third-party Python
packages are required.

```sh
./scripts/setup-hooks.sh
python3 -m unittest discover -s tests -v
python3 scripts/check_repository.py --all-history
```

Future application development will require macOS, Xcode with a Swift toolchain,
and stable Rust. Exact minimum versions and build commands will be established
and verified with the first implementation slice. Do not install scanner tools
as part of repository setup.

## Development and providers

Read [development](docs/development.md), [architecture](docs/architecture.md),
[assets](docs/assets.md), [provider design](docs/providers.md), and
[Recon Chains](docs/recon-chain.md). The first implementation will connect
SwiftUI, Rust, SQLite, and one synthetic provider in an offline vertical slice.
Only after that works will Subfinder, Nmap, and HTTPX be introduced incrementally.

## Privacy and authorization

Use MACSPLOIT only on systems you own or are explicitly authorized to assess.
Active work requires an explicit scope; discovered third-party assets do not
automatically become scan targets. Future validation/lab features remain separate
from normal reconnaissance.

Never commit API keys, passwords, tokens, cookies, credentials, private keys,
Keychain exports, `.env` files, real assessment data, or sensitive scanner output.
Runtime data belongs outside the checkout. See the
[security model](docs/security-model.md) and [repository policy](docs/repository-policy.md).
Local hooks are a defense in depth and do not replace review of every commit.

The [roadmap](docs/roadmap.md) records the planned phases. Collaborators, GitHub
Pages, releases, and visibility changes require the owner's explicit approval.
