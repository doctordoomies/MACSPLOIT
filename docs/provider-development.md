# Provider development guide

A **provider** wraps a capability — either an external security tool or a native
implementation — behind one Rust trait. The orchestrator selects providers by
**capability** (or a chain stage pins one by id) and runs them uniformly: scope
check → execute → evidence → parse → normalize → persist → events.

> Pre-1.0: this is an **internal** contract, not a stable public plugin ABI. It may
> change between minor versions.

## The trait

```rust
pub trait Provider: Send + Sync {
    fn metadata(&self) -> ProviderMetadata;
    fn installation(&self, tools: &ToolConfig) -> Installation;
    fn timeout(&self) -> Duration { Duration::from_secs(30) } // override for heavy tools
    fn execute(&self, target: &str, capability: Capability,
               inputs: &[Asset], ctx: &ProviderContext) -> Result<Execution>;
    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>>;
}
```

- **`metadata`** declares `id`, `name`, `version`, `capabilities`,
  `supported_target_types`, `risk_class`, and `offline`.
- **`installation`** returns `BuiltIn` (native), `Installed { version }`, `Missing`,
  `UnsupportedVersion`, or `ExecutionError`. Detect the tool; never install it.
- **`execute`** does the work and returns an `Execution` (command, stdout, stderr,
  exit status, timings). External tools run through the shared **process supervisor**
  (`crate::process::run`) with an argument array — never a shell.
- **`parse`** turns an `Execution` into `Discovery` values (asset type, value,
  optional source + relationship, metadata). It must treat output as **untrusted**.

The orchestrator wraps every run in a JSON **evidence envelope** (command, version,
exit, timings, raw stdout/stderr), stores it hash-verified **before** calling
`parse`, records a provider run, and persists discoveries (normalizing and
de-duplicating assets, creating relationships, and marking `in_scope`).

## Risk classes and scope

- `PASSIVE` — no contact with the target (e.g. Subfinder). Runs on any in-scope
  target.
- `ACTIVE_LOW_IMPACT` — bounded, non-intrusive contact (e.g. DNS, HTTP probe).
- `ACTIVE` — real scanning (e.g. Nmap). Requires the analyst to explicitly launch
  the chain; still filtered to per-asset scope.
- `VALIDATION` / `LAB_ONLY` — disabled in normal reconnaissance.

The orchestrator filters `inputs` to workspace scope before your `execute` runs
(host-child assets like Port/Service are scoped by their `host` metadata). Never
widen scope inside a provider.

## Capability-based selection & stage pinning

Providers are chosen by capability. When more than one provider offers a capability,
a chain stage pins the exact provider by id (`chain_stages.provider_id`). Add your
provider to `ProviderRegistry::new`.

## Bounded, hostile-output-safe parsing

- Prefer machine-readable output (JSON/JSONL/XML), never terminal text.
- Bound record count, line length, and total size; skip malformed records instead of
  failing the whole run; fail cleanly (evidence preserved) on unparseable output.
- XML: use a safe parser (we use `roxmltree`, which does not expand external
  entities). Add malformed/oversized fixtures.

## Testing (mandatory, offline)

Every provider needs tests that run with **no network**:

- Unit tests for metadata, argument construction (incl. IPv4/IPv6 where relevant),
  parsing (valid, malformed, empty, duplicate, unknown fields), and missing-tool.
- A **fake executable** (see `fixtures/fake-*.sh`) or fixtures, injected via
  `ToolConfig` overrides (`MACSPLOIT_<TOOL>` env) or a test double (the DNS provider
  uses an injectable `DnsResolver`).
- Inclusion in the Domain Recon integration test where it fits the pipeline.

## Checklist

See the provider checklist in [CONTRIBUTING.md](../CONTRIBUTING.md). Update
[providers.md](providers.md), [recon-chain.md](recon-chain.md) (if you add a stage),
and [features.md](features.md).
