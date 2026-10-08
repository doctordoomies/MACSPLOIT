# Synthetic fixtures only

Phase 0 provider tests generate invented structured output through the synthetic
provider and exercise its parser, graph ingestion, and evidence persistence.
Temporary runtime output stays outside Git. No real assessment captures belong here.

Phase 1 should add static synthetic fixtures for each real provider's supported
structured-output versions, malformed/truncated output, and scope boundaries.

`fake-user-scanner.sh` mimics user-scanner 1.5.2.1 offline (version banner, argument
handling, JSON report written to `--output`). It refuses prohibited modes
(`--cross-scan`, `--hudson`, proxies, `--allow-loud`, …) and requires the private
config that disables the upstream update check. `user-scanner/*.json` are invented
reports in the verified 1.5.2.1 schema (`*.example.test` hosts only).
