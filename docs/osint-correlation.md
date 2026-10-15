# OSINT correlation, cross-provider agreement, and aggregator decision

Status: **BETA — implementation portion of Issue #67 (umbrella #58).** Owner acceptance
of Milestone 6 is still pending; this document describes what the code does, not a
completed milestone.

## Two different questions

| Question | Mechanism | Automatic? | Can it join different identities? |
| --- | --- | --- | --- |
| "Is this the **same asset**?" (e.g. two providers report `api.example.test`) | Canonical deduplication: same asset type + canonical identity → one asset; one **observation per provider run** | Yes | **Never** |
| "Might these two **different** assets be the **same subject**?" (e.g. `@octo` and `octo@example.test`) | **Correlation** (this document) | **Never** | Only as an explicit, reviewable analyst claim |

Cross-provider agreement is represented only explicitly: when Sherlock, Maigret, and
socialscan all report `github:octo-synthetic`, or theHarvester and certificate
transparency both report `api.example.test`, the result is one canonical asset with
one observation per provider run (each with its own provider id, run id, evidence, and
per-run metadata). Agreement is visible as provenance; it never raises confidence on
its own, never creates relationships between different identities, and never creates
a correlation.

## Correlation model (core-authoritative)

Implemented in `core/src/correlation` with migration `007_correlations.sql`; exposed
over the protocol as `propose_correlation` / `review_correlation` and in every
`snapshot` as `correlations` (with review history).

A correlation is:

- **Explicit** — created only by an analyst action. No provider, parser, or chain
  creates one; the acceptance test asserts that a full four-workflow run produces
  none.
- **Evidence-backed and attributable** — it cites 1–20 observations; at least one
  observation of **each** asset is required, and **every** cited observation must
  carry evidence (an analyst-entered target alone cannot back a correlation). The
  evidence ids are stored with the correlation and remain readable after restart.
- **Confidence-aware** — `basis` (`analyst_review`, `shared_public_record`,
  `shared_identifier`) and `confidence` (`LOW`/`MEDIUM`/`HIGH`) are required. A shared
  identifier (the same handle on two platforms) is a weak signal and is **capped at
  LOW** by the core.
- **Reviewable and reversible** — it starts `PROPOSED`. Only these transitions exist:
  `PROPOSED → CONFIRMED | REJECTED`, `CONFIRMED → RETRACTED`,
  `REJECTED | RETRACTED → PROPOSED` (reopen). Each decision needs a note and is
  appended to `correlation_reviews` (never edited), emits a `CorrelationReviewed`
  event, and writes an audit record. A second proposal for the same pair (either
  order) is refused; the existing one must be reviewed instead.
- **Non-destructive** — assets, observations, relationships, and evidence are never
  merged, rewritten, or deleted by correlation. Text is bounded (1,024 bytes) and
  control characters are stripped. A workspace holds at most 500 correlations.

The app shows correlations in the OSINT section (functional controls only): propose
between two evidence-backed subject/account assets, see basis/confidence/evidence count
and the review history, and record confirm/reject/retract/reopen with a note.

## Persistence and failure semantics (acceptance coverage)

`core/tests/osint_acceptance.rs` runs Username (Sherlock), Email (socialscan), Phone
(PhoneInfoga), and Domain (theHarvester + CT) end to end in one workspace, proposes and
reviews a correlation (including over the protocol), restarts the engine, and checks
that assets (including first-seen metadata), observations, relationships, evidence,
provider runs (each distinguishable), and correlation provenance and review history are
unchanged. A second test checks that zero results, partial results, provider errors,
malformed output, a missing tool, and an unsupported version are distinct outcomes and
that every run that started keeps its evidence. Cancellation and timeouts are covered
per provider in `osint_domain.rs`, `osint_phone.rs`, and `osint_username_wave.rs`.

## Aggregator review and decision

Decision criteria applied to every candidate (any failure → not integrated):

1. Actively maintained upstream with a reviewable, versioned CLI/API.
2. A passive-only mode that the core can enforce by construction (fixed argv or fixed
   request URLs), with no hidden active scanning, DNS brute force, recursion, or
   follow-on probing.
3. Bounded, structured, stable output MACSPLOIT can parse as untrusted data.
4. No credentials, account interaction, breach/infostealer data, or private-data access.
5. Safe installation (no `curl | sh`, no background services or auto-updaters started
   by MACSPLOIT) and a license compatible with invoking it as a separate process.

| Candidate | Reviewed | Decision | Evidence |
| --- | --- | --- | --- |
| **SpiderFoot** | `smicallef/spiderfoot` v4.0 (last release 2022; last commit 2023-11-05) | **Not integrated** | Unmaintained; a 200+ module framework with its own web server and scan engine whose modules include active probing (port scans, DNS brute force, web spidering) and breach/leak lookups. A passive subset cannot be enforced by MACSPLOIT's core, and its output is a framework-specific event stream. |
| **OWASP Amass** | `owasp-amass/amass` v5.1.1 (2026-04) | **Not integrated** (for #66) | v5 runs a background `amass_engine` service with an asset database. `-passive` is documented as "deprecated since passive is the default", yet the default engine still runs DNS plugins (resolution, reverse, SRV/TXT), horizontal scope expansion (related organizations/IPs/certificates; `-rigid` only disables expansion), and `-active` / `-brute` / `-alts` options exist. There is no switch MACSPLOIT can rely on to guarantee "no active DNS probing, no recursion". |
| **Holehe** (for #64) | `megadose/holehe` (last commit 2024-09-10) | **Not integrated** | Works by driving third-party signup / password-reset flows per site — account interaction that can notify the subject. Email OSINT uses user-scanner and socialscan (availability checks without login or recovery flows). |
| **Read-only public APIs** | IANA RDAP bootstrap + registry RDAP; crt.sh CT search | **Integrated natively** | Fixed HTTPS URLs, bounded bodies/redirects/timeouts, cancellation, raw bytes kept as evidence; implemented in Rust (`native_rdap`, `native_ct`). theHarvester (4.10/4.11) is integrated with a fixed key-less passive source allow-list as the aggregator of public passive sources. |

Revisit Amass if upstream adds an enforceable passive-only engine mode with structured
output, and SpiderFoot only if maintenance resumes and a module allow-list can be
enforced from the command line.

## Limits and non-goals

- No automatic correlation suggestions; MACSPLOIT does not score identities.
- No pivots: correlation never starts another OSINT run.
- Live endpoints (crt.sh, IANA/registry RDAP) could not be exercised from the
  development environment (egress-blocked); behavior is verified against documented
  formats and offline fixtures. A real-network run is part of owner acceptance.
