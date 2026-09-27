# Provider design

Status: internal contract proposal; no providers are implemented or installed.

A provider describes its name, version, homepage, license, target types,
capabilities, risk class, dependencies, installation method, resolved executable,
and supported parser versions. Its operations cover metadata, support checks,
installation status, command construction, execution through the supervisor,
output parsing, and normalization.

Capabilities describe work such as SUBDOMAIN_DISCOVERY, DNS_RESOLUTION,
PORT_DISCOVERY, SERVICE_FINGERPRINTING, and HTTP_PROBING. Recon Chains request
capabilities; provider selection does not hardcode tool names into the engine.

Risk classes are PASSIVE, ACTIVE_LOW_IMPACT, ACTIVE, VALIDATION, and LAB_ONLY.
Scope and user authorization govern execution. VALIDATION and LAB_ONLY are
excluded from standard reconnaissance. Tool installation must display its source
and exact command for explicit approval; do not silently install software.

Discover executables through PATH, the detected Homebrew prefix, managed-tool
storage, and known locations. Do not assume `/usr/local/bin` or system Python.
Build executable/argument arrays, never shell-interpolated strings.

The supervisor owns subprocess lifetime, cancellation, timeout, output capture,
exit status, and concurrency. Parsers consume bounded structured output and
produce validated discoveries, relationships, findings, and evidence references.
Preserve raw stdout, stderr, structured files, tool version, arguments, target,
and timestamps even when parsing fails. The ordinary log view must protect
secret values without destroying the separately protected original evidence.

Begin with one deterministic synthetic provider that requires no network or
external binary. Introduce Subfinder, Nmap, and HTTPX individually after the
foundation works. Each real adapter needs synthetic fixtures for normal output,
malformed/truncated input, supported versions, exit failures, scope boundaries,
and cancellation. Prefer JSON/XML over human-oriented terminal text.

A future `provider.toml` may describe plugins. Do not publish or stabilize a
third-party ABI until internal adapters establish the right interface.
