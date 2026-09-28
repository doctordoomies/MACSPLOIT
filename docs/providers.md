# Providers

Status: **IMPLEMENTED** internal Rust provider contract and one offline provider.

The `Provider` trait separates `metadata`, `execute`, and `parse`. Metadata exposes
ID, name, description, version, capabilities, supported target types, and risk.
A registry selects by capability and supported target type; SwiftUI never selects
executables or parses raw provider output. This is an internal interface, not a
third-party plugin ABI.

Implemented capabilities: SUBDOMAIN_DISCOVERY, DNS_RESOLUTION,
SERVICE_FINGERPRINTING. Risk classes: PASSIVE, ACTIVE_LOW_IMPACT, ACTIVE,
VALIDATION, LAB_ONLY. Active classes require explicit authorization and scope;
validation/lab are rejected in Phase 0. No active provider is registered.

## SyntheticDiscoveryProvider

The only implementation is `synthetic`, version `1.0.0`, risk PASSIVE. It accepts
`example.test` and produces invented JSON without DNS, sockets, external requests,
subprocesses, or installed tools. Resolution and service stages consume scoped
assets discovered earlier in the current chain. All addresses are documentation
addresses in `192.0.2.0/24`.

The adapter deliberately reports duplicate/case-variant subdomains to exercise
normalization while retaining observations. Its parser validates the synthetic
output envelope, size, and discovery count. The core validates asset identities
and relationship sources transactionally before persistence. Tests cover metadata,
structured parsing, malformed input, graph shape, deduplication, and evidence.

Each capability execution persists a provider-run record with identity/version,
input, start/end, status, evidence reference, and exit status. Raw JSON is hashed
and recorded before parsing. The synthetic success exit status is 0; no real
process is implied. Provider records/evidence are separate from ordinary helper
logs and user-action audit records.

## Next adapter boundary

**PLANNED — Phase 1:** begin with a Subfinder JSON parser and synthetic fixtures
for supported output, malformed/truncated lines, duplicate observations, scope,
and process failures. Add an execution supervisor for executable paths plus
argument arrays, timeout/cancellation, bounded stdout/stderr, tool version, exit
code, and explicit installation/run approval. Only then enable authorized scoped
execution. Follow with Nmap and HTTPX incrementally.

Phase 0 checks cancellation and its elapsed budget between stages and around
immediate synthetic execution. It does not interrupt arbitrary blocking external
providers; that supervisor is a prerequisite for real adapters. Expand the internal
execution context as needed without moving scheduling, persistence, evidence, or
provider-specific parsing into SwiftUI.

**FUTURE:** executable discovery, approved installation/update tooling, dependency
and license metadata, version compatibility, managed tools, public provider SDK.
No `provider.toml` contract or installer is frozen now. Never silently install a
tool or interpolate target input into a shell.
