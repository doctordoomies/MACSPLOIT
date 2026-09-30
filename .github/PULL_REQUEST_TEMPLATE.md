<!-- Thanks for contributing to MACSPLOIT! Please complete the checklist. -->

## Summary

<!-- What does this PR change and why? -->

## Related issues

<!-- e.g. Closes #123 -->

## Checklist

- [ ] Tests added or updated
- [ ] All automated tool tests are **offline** (fake executables / fixtures) — no
      network scanning or real DNS
- [ ] No real target data, client information, or secrets in code, tests, or fixtures
- [ ] Docs updated (including `docs/features.md` if status changed)
- [ ] Scope and risk-class implications reviewed
- [ ] Provider/tool output is treated as untrusted (bounded, validated, no shell)
- [ ] `./scripts/test.sh` passes locally (Rust + Swift + repository-policy)
- [ ] `cargo fmt --all -- --check` and `cargo clippy` clean
- [ ] The repository audit passes (`python3 scripts/check_repository.py --all-history`)

## Security / scope notes

<!-- Any impact on scope enforcement, active scanning, evidence handling, or the
     process supervisor? If none, say "none". -->
