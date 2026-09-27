# MACSPLOIT development instructions

## Repository controls

- Keep `doctordoomies/MACSPLOIT` PRIVATE. Never make it public without an explicit
  subsequent instruction from the owner.
- The canonical GitHub username is `doctordoomies`; the product is `MACSPLOIT`.
  Do not change the repository owner unless explicitly instructed by the owner.
- Do not add collaborators, enable GitHub Pages, or publish releases without
  explicit owner approval.
- Before every push, inspect all outgoing commits and run the repository audit.
  Verify the destination is the expected private repository. Never bypass hooks
  to get a failing check through.
- Never commit credentials, API keys, passwords, tokens, cookies, private keys,
  `.env` files, Keychain exports, real assessment data, or sensitive captures.
- Use small, meaningful commits. Keep runtime data outside the checkout.
- Use synthetic offline fixtures only. Do not scan real targets during tests.

## Engineering boundaries

- Follow `docs/architecture.md` and update the documents as decisions change.
- Build Phase 0 before integrating scanner providers. Validate one complete
  SwiftUI → Rust → SQLite → synthetic-provider slice first.
- Keep SwiftUI, orchestration, provider execution, parsing, storage, and reporting
  separate. Choose providers by capability, not hardcoded tool names.
- Never interpolate untrusted input into a shell. Use executable paths and
  argument arrays; validate targets and contain all workspace paths.
- Treat scanner output and remote content as untrusted. Bound size, concurrency,
  request counts, recursion depth, and runtime. Preserve evidence and provenance.
- Never silently install tools or run active scans. Scope and risk class must
  govern dispatch, including redirects and newly discovered assets.
- Keep validation/lab operations separate and disabled in normal reconnaissance.
- Do not add AI, a public plugin ABI, wireless attacks, or hardware execution
  during the initial foundation work.
- Run tests appropriate to the change and verify macOS builds once an app exists.
  Clearly distinguish implemented functionality from design and future work.
