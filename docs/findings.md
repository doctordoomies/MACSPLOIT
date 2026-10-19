# Findings and the normalized result contract

Status: **BETA — Milestone 2/4 foundation (Issue #76) plus Findings hardening (Issue #79
and the deterministic Level‑1 of #81), parent #68. Owner acceptance pending.** This is the
foundation plus deterministic draft authoring: manual/analyst Findings, a shared typed
result projection, and a non‑persisted draft the core builds from durable context so the
editor opens already populated. Reviewed scanner‑proposed Findings (TLS, Nuclei, analyzers)
and optional AI writing assistance (Level 2/3 of #81) come later.

## Observation vs Evidence vs Finding

These three are deliberately distinct, and keeping them distinct is the point of this
layer:

- **Observation** — *a provider-reported fact.* "Native HTTP saw `https://example.test/`
  respond with HTTP 200 and an observed Content-Type." It carries provenance (provider, run) and, in
  general, a reference to the evidence that backs it. Observations are produced by
  providers; MACSPLOIT never invents them.
- **Evidence** — *the retained source material that supports an observation.* The raw,
  hashed, integrity-checked provider output (the HTTP response
  envelope or a structured provider report). Evidence is proof; it is never edited.
- **Finding** — *a reviewable security conclusion an analyst draws from evidence.*
  "Expired TLS certificate — Medium severity, High confidence, Open." A Finding
  **references** the affected assets and the evidence; it never copies raw provider
  stdout into its text. Findings are created only by an explicit analyst action.

> Observation answers *"what did the tool see?"* Evidence is *the proof.* Finding is
> *"what security conclusion does the analyst draw from that evidence?"*

## Provider → normalized records → projection → Finding

```
Provider
  → Parser / normalizer
  → typed durable records  (Asset / Observation / Relationship / Evidence)
  → ResultProjection       (a read model over those records)
  → Finding                (references those durable records)
```

The durable workspace graph is the single source of truth. There is no parallel
"results" database. A `ResultProjection` is a **read model** derived from durable
observations for one chain run — it stores nothing new. The Create Finding path consumes this projection. Existing Recon and OSINT renderers
continue consuming their working chain-results/typed OSINT read models; migrating those
renderers to the shared projection is a follow-up. Future consumers can use these
durable records without parsing console output. The live console remains execution
visibility only; neither it nor raw Evidence is the result database.

## The Finding entity (`core/src/findings`, migration 008)

Three **independent** typed dimensions (never collapsed):

- **Severity** — `INFORMATIONAL | LOW | MEDIUM | HIGH | CRITICAL` (impact).
- **Confidence** — `LOW | MEDIUM | HIGH | CONFIRMED` (the analyst's confidence it is
  real; distinct from an Observation's provider-reported confidence).
- **Status** — a validated lifecycle: `DRAFT | OPEN | CONFIRMED | INFORMATIONAL |
  FALSE_POSITIVE | RESOLVED | RETEST_PASSED`. Only documented transitions apply, enforced
  in the Rust core (Swift only offers the transitions the core will accept). A finding is
  created as DRAFT, OPEN, CONFIRMED, or INFORMATIONAL.

A Finding also has: title, description, reproduction/verification notes, remediation
notes; zero-or-more **affected canonical assets** (`finding_assets`, at most one primary
for presentation); **multiple Evidence references** (`finding_evidence`; dedup- and
unlink-safe — the Evidence itself is never deleted); bounded **tags** and **CVE/CWE**
identifiers (shape-validated — a syntactically valid id never implies applicability);
immutable **source provider/run** attribution when seeded from a result (kept separate
from analyst-written text); and an append-only **history** (`finding_history`: creation,
status, severity/confidence, edits, evidence links) that survives restart.

Everything is bounded (title/text/tags/identifier lengths and counts) so untrusted
scanner output can never push megabytes into a Finding field — large raw output belongs
in Evidence. Every asset/evidence/run reference is validated to exist **in the same
workspace**; cross-workspace references are rejected in the core. No HTML is rendered.

## Creating a Finding: deterministic drafts (`core/src/draft`)

The analyst never has to create a blank Finding and retype facts MACSPLOIT already holds.
**Create Finding** — from one result, several selected results, a whole run, or a single
asset — hands a typed selection of durable context to the core, which builds a
deterministic, **non‑persisted** `FindingDraft` and returns it. The structured editor then
opens **already populated**; the analyst reviews or changes anything and presses **Create**
immediately — there is no required intermediate Edit step. A manual "Blank finding" is still
available.

```
result / selected results / run / asset
  → draft_finding   (core validates the selection, read-only)
  → FindingDraft    (typed, non-persisted — NOT a Finding)
  → editor opens populated
  → analyst reviews / edits
  → Create          (ordinary transactional create_finding)
```

Each Recon/OSINT result row and the asset inspector expose a direct **Create Finding** that
drafts from exactly that result and opens the editor immediately — no selection step, and no
primary chooser unless the draft legitimately has several affected assets. The multi‑select
picker and the run‑scoped flow remain for building a Finding from several results or part of
a whole run. (Phone‑number facts are a per‑source summary with no single durable
per‑observation row, so they keep only the run‑level action — a per‑fact surface is a #80
follow‑up.) All entry points converge on one shared, token‑guarded draft path.

A draft is **not** a Finding: `draft_finding` opens the workspace store read‑only, inserts
nothing, and performs no network activity. Every referenced observation/asset/evidence id is
validated against the workspace — and, when run‑scoped, against the run — by the core; a
wrong‑run result, a cross‑workspace reference, an empty selection, or an oversized selection
is rejected. If drafting fails the editor shows an explicit error and offers a blank
finding; it never silently opens empty.

**MACSPLOIT never invents a vulnerability.** Deterministic drafting has two classes:

- **Generic observation draft** (all current Recon/OSINT results). The draft is a *factual,
  informational* note: a concise factual title ("`…` (Website) observed via native_http"),
  a description summarizing the normalized facts and which provider reported them, mechanical
  re‑run verification guidance (never exploit steps), **severity INFORMATIONAL**, the safest
  **confidence (LOW)** — a Finding's confidence is the analyst's judgment, never a provider's
  self‑report — **empty remediation**, and **no CVE/CWE/tags**. It never claims a
  vulnerability, exposure, compromise, or "close this port."
- **Reviewed‑rule draft** (future). A reviewed TLS/Nuclei/native rule (#83–#85) may attach a
  `ReviewedFindingHint` carrying a proposed title, severity, confidence, status, description,
  reproduction, remediation and validated CVE/CWE/tags. The draft builder already consumes it
  so richer drafts need no second pipeline. A hint has **no wire path** and can only come from
  trusted in‑core rule metadata — never from arbitrary provider text — so no scanner can turn
  stdout into a severity or an identifier. No rule emits hints yet.

Affected assets come from the selected observations plus any explicitly chosen assets
(de‑duplicated); the analyst picks the primary (or the core chooses deterministically) and
may add/remove assets without dropping the rest. Evidence comes from the selected
observations plus any explicitly chosen evidence. Source provider/run are attributed only
when every selected result shares one provider run, so attribution always matches the
findings store's provider/run rule. Draft title/description/reproduction are bounded, and a
run's results are enumerated up to a cap with a summarizing remainder — a huge run is bounded
or rejected, never turned into an unbounded wall of text. The draft is derived purely from
durable normalized state, so it is identical whether or not any console output exists and
survives restart.

## Protocol (internal v1, additive)

`create_finding`, `update_finding` (analyst fields only — not status, not source
attribution), `set_finding_status` (validated transition + note), `link_finding_evidence`
/ `unlink_finding_evidence`, `result_projection` (the typed read model for a chain), and
`draft_finding` (a read‑only, deterministic `FindingDraft` from a typed selection; creates
nothing). Findings are included in the workspace snapshot (list/get/history for free). See
[internal-protocol-v1](../schemas/internal-protocol-v1.md).

## Not yet (deliberately deferred)

No automated Finding creation — missing headers, open ports, versions, OSINT facts, and
banners are **not** turned into Findings yet, not even "obvious" ones. Those arrive later
as reviewed Finding rules/scanners (TLS, Nuclei, native analyzers, CVE enrichment,
Semgrep, dependency/secret scanners), each of which will create **proposed, reviewable**
Findings through this same durable model — never its own storage format. Reports, export,
and AI are not built here, but the durable records are structured so a future consumer can
retrieve Findings (with assets, evidence, provenance, severity/confidence/status,
identifiers, history) without scraping the UI or parsing console text.

## Lifecycle transitions

Rust is authoritative. Initial states: DRAFT, OPEN, CONFIRMED or INFORMATIONAL.
Every transition requires a 1–1,024-byte review note; self-transitions are rejected.

| From | Allowed next states |
| --- | --- |
| DRAFT | OPEN, INFORMATIONAL, FALSE_POSITIVE |
| OPEN | CONFIRMED, INFORMATIONAL, FALSE_POSITIVE, RESOLVED |
| CONFIRMED | RESOLVED, FALSE_POSITIVE |
| INFORMATIONAL | OPEN, FALSE_POSITIVE |
| FALSE_POSITIVE | OPEN |
| RESOLVED | RETEST_PASSED, OPEN |
| RETEST_PASSED | OPEN |

## Validation and persistence contract

- Title: 1–200 UTF-8 bytes. Description, reproduction and remediation: each 0–8,192 bytes.
- Tags: at most 24, each 1–48 bytes. CVE and CWE lists: at most 32 each, IDs at most
  32 bytes, normalized to uppercase and checked for shape only. Blank optional lists
  remain empty. Control characters are replaced with spaces and surrounding whitespace
  is trimmed in analyst text. Multiline input is stored as plain text, never executed HTML.
- Up to 20 affected assets and 50 Evidence references; duplicate IDs are deduplicated.
  Initial additional-asset and Evidence input lists are bounded before deduplication.
  A blank manual Finding may be unlinked. Asset links are set at creation in this slice;
  post-creation asset-link editing is deferred. Evidence supports idempotent link/unlink.
- At most 2,000 Findings per workspace. All mutations and their history/events commit
  atomically. Invalid updates roll back. A source run must exist in the same workspace;
  an explicitly supplied source provider must match that provider run. Source attribution
  cannot be changed through the edit operation.
- History records creation, lifecycle transitions and notes, severity/confidence old/new
  values, edit markers, and Evidence link changes. It does not retain full previous text
  bodies or implement project-wide event sourcing. There is no Finding deletion API.
  Unlinking Evidence leaves the retained, hash-verifiable Evidence untouched.
- Migration 008 adds only `findings`, `finding_assets`, `finding_evidence`, and
  `finding_history`; migrations 001–007 are unchanged. Existing Recon/OSINT records and
  Evidence remain intact. Snapshots expose Findings with all links and history;
  older snapshots without `findings` decode as empty.
- Malformed stored enums, UUIDs and identifier/tag array shapes produce errors rather
  than silently substituting low severity, draft status, empty links or empty arrays.
  Finding events contain IDs and small status summaries, not description or Evidence bodies.

## ResultProjection contract and limits

`result_projection(workspace_id, chain_id)` returns `{workspace_id, chain_id,
chain_name, items}`. Items carry a typed `kind` (`ASSET_OBSERVATION` or
`RELATIONSHIP_OBSERVATION`), durable Observation/Asset IDs, asset type/identity,
optional source asset, provider-run/provider, Evidence reference, provider-reported
confidence, timestamp, observed value and supplemental normalized `metadata`.
A relationship kind requires the existing same-run/same-Evidence relationship
provenance; a source-context asset alone is not proof of an edge. The projection
contains no console/stdout or duplicate durable result table.

The query opens SQLite read-only in one transaction; it never migrates, changes scope,
launches a provider or performs network activity. Unknown/wrong-workspace chains are
rejected. Database errors propagate explicitly. At most 10,000 items and 6 MiB of
serialized projection data are returned; overflow is `ResultsTooLarge`, never silent
truncation. Supplemental metadata over 32 KiB is omitted as null with
`metadata_omitted: true`; absent historical metadata remains null with false. Canonical
records and Evidence remain available independently. Metadata is normalized untrusted
data, not guaranteed secret-free: display consumers redact URLs and must never execute it.

The picker loads only the selected workspace/run, clears old results immediately,
and guards request tokens/cancellation including A→B→A selection. URL reference labels
redact query strings/userinfo/fragments and remove control/bidi characters. Findings
text is analyst-authored plain text. No raw Evidence is pasted into the editor.

## Owner acceptance (still pending; Issue #76 stays open)

1. Open an existing authorized workspace, select Recon and a completed run, choose
   **Create Finding**, select one result, and confirm the editor opens **already
   populated**: a factual title, INFORMATIONAL severity (for generic recon), the affected
   Asset, supporting Evidence, source provider/run, and a factual description — no invented
   vulnerability, remediation, or CVE. Press **Create** without changing anything and
   confirm it appears in **Findings**.
2. Repeat, this time editing the title/description/severity before **Create**; confirm your
   changes persist and are not overwritten by draft defaults.
3. Choose **Create Finding** on a run, select several results, include multiple Assets, and
   change the primary Asset; confirm the created Finding retains all selected context.
4. Open its affected Asset and linked Evidence. Link a second Evidence item, then unlink
   one and confirm the independent Evidence record is still available.
5. Edit severity/confidence independently. Change status with a review note; exercise
   Open → Confirmed → Resolved → Retest passed, and reopen a false positive separately.
6. Quit/reopen MACSPLOIT and select the workspace. Verify the Finding, analyst‑edited text,
   all affected Assets, primary Asset, Evidence, source provenance, status and history
   remain.
7. From an Asset inspector, use **Create Finding** and confirm a factual informational draft
   opens populated. Use **+ New Finding → Blank finding** and confirm a manual, empty editor
   is still available.
8. Check Username/Email account results, actual Phone source facts, and Domain discoveries;
   use **Create Finding** on a completed OSINT run as a compatibility check.

Automated coverage uses synthetic/fake-provider fixtures and the real Swift→Rust→SQLite
bridge, including restart. It does not claim the on-screen owner walkthrough is complete.
