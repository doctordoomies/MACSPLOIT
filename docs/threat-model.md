# MACSPLOIT threat model

MACSPLOIT runs external security tools and parses **hostile remote content**. This
document states what we defend against, how, and the known limitations. It
complements the [security model](security-model.md).

## Assets to protect

- The user's machine and account (no privilege escalation, no arbitrary code
  execution triggered by target/provider content).
- Workspace integrity and isolation (no cross-workspace access, no evidence
  tampering).
- Scope as a safety boundary (only authorized hosts are actively contacted).
- The user's privacy (no telemetry; sensitive data stays local).

## Adversaries & vectors

### 1. Malicious targets / provider output
Targets control DNS answers, banners, HTTP responses, and therefore much of what
providers emit. **Mitigations:** targets are validated/normalized before use (cannot
become shell syntax or options); all tool output is treated as untrusted and parsed
with bounded size/line/record limits; malformed records are skipped; XML is parsed
with a non-entity-expanding parser (`roxmltree`); JSON/JSONL parsing is size-bounded.
**Limitation:** a compromised *tool binary* is outside our trust boundary.

### 2. Malicious providers / tool binaries
MACSPLOIT executes whatever `subfinder`/`nmap`/`httpx` binary it finds. **Mitigations:**
executable discovery only accepts regular, owner-executable, non-symlink files;
execution uses an argument array (no shell) through a supervisor with bounded output,
per-provider timeouts, and process-group termination. **Limitation:** MACSPLOIT
trusts the tools the user installs; verify their provenance.

### 3. Malicious workspace data / filenames / paths
**Mitigations:** workspace and evidence paths are contained; symlinks at workspace/
evidence boundaries are rejected; evidence IDs resolve only to their expected
relative paths; parameterized SQL throughout. **Limitation:** an attacker who already
has local code execution as the user is out of scope.

### 4. Scope bypass
The most important safety boundary. **Mitigations:** scope checks use exact hosts,
wildcard label boundaries, and CIDR (IPv4/IPv6); active providers are filtered to
per-asset scope so a resolved third-party IP is not scanned; scope is never widened
automatically. **Limitation:** HTTP redirect-target re-checking is planned; today
providers operate on already-scoped assets.

### 5. Malicious contributors / dependency & supply-chain compromise
**Mitigations:** offline-only tests; a repository audit over full history for
secrets/sensitive data; least-privilege CI; pinned/So-reviewed dependencies; planned
`cargo audit`/`cargo deny` and Dependabot. **Limitation:** transitive dependency
trust is inherent to any build.

### 6. GitHub Actions risks
**Mitigations:** workflows default to `contents: read`; no `pull_request_target`
with secrets; contributor-controlled code does not run with write tokens; actions
pinned. See [.github/workflows](../.github/workflows).

### 7. Evidence tampering / integrity
**Mitigations:** evidence is SHA-256 verified on read; integrity mismatch is an
error, not silently ignored.

## Local privilege boundaries

MACSPLOIT runs as the current user, ad-hoc signed and unsandboxed for development.
It requires **no root** — the default Nmap profile is an unprivileged connect scan.
It does not modify system settings or request elevation.

## Out of scope (known limitations)

- A malicious local user already running as the account.
- Compromised external tool binaries or a compromised OS.
- Hardening against a fully hostile macOS environment.
- Redirect-based scope re-checks, per-host rate limits, and a general dependency
  scheduler are planned, not yet implemented.
