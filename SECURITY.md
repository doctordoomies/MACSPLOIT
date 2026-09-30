# Security Policy

This policy is about vulnerabilities **in MACSPLOIT itself** (the application, the
Rust core, the provider integrations, the build/release tooling).

It is **not** about vulnerabilities that MACSPLOIT *finds* in your targets — those
belong to the systems you are assessing, not here.

## What counts as a MACSPLOIT security vulnerability

Examples of issues we want reported privately:

- Command or argument injection through targets, scope, workspace names, or
  provider output.
- Path traversal, symlink attacks, or evidence/workspace containment escapes.
- Scope-enforcement bypasses (e.g. getting an out-of-scope host actively scanned).
- Parser hazards (XML/JSON/JSONL) leading to crashes, resource exhaustion, or code
  execution when processing hostile provider output.
- Cross-workspace data access, or evidence integrity/tampering issues.
- Supply-chain issues in the build or release pipeline.

## Supported versions

MACSPLOIT is pre-1.0. Only the latest released version and `main` receive security
fixes. Please test against the latest `main` before reporting where practical.

## How to report

**Please do not open a public issue for an undisclosed vulnerability.**

- Preferred: **GitHub Private Vulnerability Reporting** — on the repository's
  **Security** tab, choose **Report a vulnerability**. (This is enabled once the
  repository is public.)
- Include: affected version/commit, macOS version and architecture, a clear
  description, reproduction steps, and impact. **Remove any real target data,
  captures, credentials, or tokens** from your report.

## Process and expectations

This is a small, volunteer-maintained project, so we cannot promise fixed
timelines. We will make a good-faith effort to:

1. Acknowledge your report,
2. Confirm the issue and assess severity,
3. Develop and release a fix, and
4. Credit you (if you wish) once a fix is available.

We ask that you give us a reasonable opportunity to remediate before any public
disclosure. Thank you for helping keep MACSPLOIT and its users safe.
