# MACSPLOIT Roadmap

> **Canonical execution plan**
>
> Master owner-facing tracker: **Issue #27 — Roadmap v2: canonical execution plan and milestone tracker**
>
> This document controls MACSPLOIT's development order. It is not a wishlist.
> `docs/features.md` remains the authoritative statement of what the code can do
> **today**; this roadmap defines what comes next, why it comes next, and the gate
> that must be satisfied before the project advances.

## Roadmap authority

The project follows these rules:

1. **One active product milestone at a time.** A later milestone does not begin merely
   because it is interesting, easy, or has an open issue.
2. **New ideas are placed on the roadmap before implementation.** Opening an issue does
   not make it the next task.
3. **Roadmap order changes are intentional changes.** Reprioritization requires updating
   this document, not silently starting later work.
4. **Two implementation PRs may run in parallel only when they are low-conflict and
   belong to the active milestone or to an explicitly allowed maintenance track.**
5. **Agents do not choose their own roadmap work.** Claude, Codex, or another agent must
   be assigned a roadmap item by the owner and must read this document, the relevant
   issue, `docs/features.md`, and current `main` before coding.
6. **Agents never merge their own feature PRs.** Owner review remains the merge gate.
7. **Every milestone has an exit condition.** "Most of it works" is not enough to advance.
8. **Completed work is reflected in both places:** implementation status in
   `docs/features.md`, and milestone progress here.

If a new feature does not clearly fit a milestone, first decide where it belongs.
Do not create a new development track by accident.

---

## Product principles

These principles apply to every milestone and provider.

### Explicit authorization

Scope is a core execution boundary, not just workspace metadata. Network activity
must be initiated by the analyst and checked against authorized scope before dispatch.

### Evidence first

Provider output is preserved before interpretation when practical. Normalized assets,
relationships, findings, and observations should be traceable to provider runs and
evidence.

### Local first

MACSPLOIT remains a native local workbench. Public Internet exposure must never be a
requirement for assessing an application that can be tested locally.

### Bounded behavior

Network providers must have understandable bounds: targets, time, requests,
concurrency, output, recursion, redirects, or equivalent limits appropriate to the
provider.

### No hidden automation

Adding a target, importing a program, or discovering an asset must not silently launch
additional active providers.

### Uncertainty stays visible

A fingerprint, username match, historical URL, automated finding, or OSINT correlation
is not silently promoted into certainty. Confidence and provenance remain separate.

### Specialist tools, shared model

MACSPLOIT is not trying to reimplement every security tool. It integrates specialist
providers into one scope-aware asset, evidence, finding, and reporting model.

### AI comes after the workbench

AI assistance must operate through the same permissioned MACSPLOIT boundaries as a
human analyst. The project does not skip core product gaps in order to build agents.

---

## Status vocabulary

| Status | Meaning |
| --- | --- |
| **DONE** | Merged to `main`, documented, and passing project gates |
| **MERGE GATE** | Implemented in an open PR; awaiting final review/checks |
| **ACTIVE** | Current product milestone; implementation work may be assigned |
| **NEXT** | Begins only after the active milestone exits |
| **QUEUED** | Ordered future milestone |
| **FUTURE** | Explicitly deferred; design may be recorded but implementation does not begin |
| **HOLD** | Intentionally paused pending a product/security decision |

---

## Definition of done

A roadmap feature is not complete merely because a provider executes once.

Unless a milestone explicitly says otherwise, a user-facing feature is done only when
all applicable items are satisfied:

- core behavior is implemented behind the existing typed architecture;
- scope/risk rules are enforced in the Rust core, not only in SwiftUI;
- network/process behavior is bounded and cancellable;
- evidence/provenance is retained;
- normalized assets, observations, relationships, or findings are persisted correctly;
- failure states are understandable and durable;
- the macOS UI provides a usable path to the feature;
- automated tests do not require live third-party targets;
- restart/persistence behavior is covered where applicable;
- documentation and `docs/features.md` match reality;
- repository policy, identity audit, Rust, Swift, Python, build, CI, and CodeQL gates pass;
- a visual/manual acceptance check is performed for meaningful UI changes when feasible;
- the owner reviews and merges the PR.

A future agent handoff should reference this definition rather than inventing a weaker
one.

---

# Current baseline

MACSPLOIT is already a functional reconnaissance workbench, not only a UI prototype.

## DONE

- Native SwiftUI app + Rust helper protocol
- Per-workspace SQLite persistence
- Editable authorized scope
- Target classification for domain, hostname, URL, IP, CIDR, email, username, and
  related model types
- Asset graph, relationships, observations, evidence, provenance, activity/events
- Synthetic Recon
- DNS Recon with built-in A/AAAA resolution
- Domain Recon:
  - Subfinder
  - Native DNS
  - Nmap
  - HTTPX
- Web Recon with Katana
- Native Web Analysis:
  - response metadata
  - security headers
  - cookie security flags
  - CORS
  - redirects
  - robots.txt
- Phase 2C Content Discovery with bounded ffuf and analyst-selected wordlists
- Path-aware CI and repository security checks

## Newly completed during this roadmap review

- **Tool Manager / Provider Center — PR #26 / Issue #24**
  - merged to `main`;
  - global provider inventory;
  - status/version/path/help;
  - generic future-provider rendering;
  - copy-only setup commands;
  - no automatic installer.

## Important gaps discovered during the product review

- no first-class direct-IP recon workflow;
- localhost/private targets are not yet a fully supported and tested product path;
- bug bounty program context is not modeled;
- there is no Findings system yet;
- OSINT target types exist, but OSINT providers are not implemented;
- reports/exports are not implemented;
- historical URLs, JavaScript analysis, API discovery, and screenshots remain planned.

These gaps define the next roadmap order.

---

# Milestone 0 — Consolidate the current beta

**Status: ACTIVE until the merge gate is complete**

This milestone closes the current development burst before new product work starts.

## Scope

- Verify current `main` after the Tool Manager merge.
- Complete the CodeQL ownership cutover so the advanced workflow is authoritative and
  the duplicate default setup no longer runs.
- Confirm the required CI gate still behaves correctly after the cutover.
- Reconcile stale maintenance issues:
  - Issue #17 ("Make Checks Faster") can be closed once the optimized CI state is
    confirmed.
- Do not start a new provider merely to keep an agent busy while this gate is red.

## Exit condition

- Tool Manager remains healthy on `main`.
- Main CI is green.
- Advanced CodeQL is green and duplicate default CodeQL is disabled.
- No unresolved regression from Phase 2C or Tool Manager.
- The roadmap PR itself is merged and becomes authoritative.

---

# Milestone 1 — Real-target usability

**Status: NEXT**

The goal is simple: common authorized targets should work directly without artificial
dependencies such as requiring public DNS first.

## 1.1 Localhost and private targets

**Existing issue: #20 — implemented in an open PR (not yet merged).** Direct IP Recon (1.2)
remains the next Milestone 1 implementation item; Milestone 1 is not yet complete.

Support first-class, explicitly scoped web targets such as:

- `http://localhost:3000`
- `http://127.0.0.1:8080`
- `http://[::1]:8080`
- `http://app.localhost:5173`
- custom `/etc/hosts` development names
- explicitly scoped RFC1918/private IP addresses and custom ports

Requirements:

- Web Analysis works against authorized local targets.
- Web Recon works against authorized local targets.
- Content Discovery works against authorized local targets.
- Public DNS is not a prerequisite.
- Loopback/private status never implies authorization.
- Cross-host redirects/discoveries remain scope checked.
- Metadata/link-local targets are not silently probed.
- TLS verification remains on by default; self-signed TLS requires a later explicit
  trust design rather than a global bypass.

## 1.2 Direct IP Recon

Add an explicit workflow for a selected, in-scope IP address:

```text
IPAddress
  → Nmap
  → Port / Service
  → HTTPX where applicable
  → Website / Technology
```

Requirements:

- IPv4 and IPv6 support.
- No DNS prerequisite.
- Existing conservative Nmap profile remains the default.
- Scope is checked directly against the IP target.
- Provider results use the existing asset/evidence model.
- The UI clearly distinguishes direct IP Recon from Domain Recon.

**CIDR note:** CIDR remains a valid scope primitive. Broad CIDR/network inventory is
not automatically enabled by this milestone; that receives its own later design so a
scope range cannot accidentally become a mass-scan instruction.

## 1.3 Real-target acceptance matrix

Add/maintain an acceptance matrix covering at minimum:

- domain;
- hostname;
- URL;
- localhost URL;
- private URL;
- IPv4;
- IPv6;
- custom port.

Automated tests remain offline/fake-provider based. Manual acceptance uses only owned or
explicitly authorized targets.

## Exit condition

An analyst can begin from an authorized **domain, URL, IP, or local application** and
reach an appropriate real workflow without creating an artificial public deployment or
DNS dependency.

---

# Milestone 2 — Bug bounty workbench + Findings foundation

**Status: QUEUED**

Recon becomes substantially more useful when the workspace understands the engagement
and can store conclusions, not only discoveries.

## 2.1 Workspace profiles

Add lightweight workspace profiles/templates such as:

- General Assessment
- Bug Bounty
- Local Application
- Lab

Profiles are metadata and UX defaults. They do **not** weaken or widen authorization.

## 2.2 Bug bounty program context

For a Bug Bounty workspace, support analyst-entered context such as:

- program name;
- program/platform URL;
- notes/rules;
- in-scope entries;
- out-of-scope notes;
- rate-limit/testing notes;
- testing window;
- source/repository reference when supplied by the program.

Do not automatically scrape or reinterpret program rules in the first implementation.
The analyst remains responsible for authorization.

## 2.3 Findings foundation

Create a durable Findings model before adding vulnerability scanners.

A finding should support, at minimum:

- title;
- affected asset/target;
- severity;
- **separate confidence**;
- status;
- description;
- reproduction/verification notes;
- remediation notes;
- evidence references;
- provider/source attribution;
- timestamps;
- optional tags/CWE/CVE identifiers when genuinely known.

First implementation should allow **manual findings** and evidence linking. Automated
providers can populate the same model later.

## 2.4 Finding lifecycle

Support clear states such as:

- Draft
- Open
- Confirmed
- Informational
- False Positive
- Resolved / Retest Passed

Do not conflate severity, confidence, and lifecycle state.

## Exit condition

A researcher can create a bug-bounty/local workspace, run recon, turn evidence into a
persistent finding, quit/reopen MACSPLOIT, and continue the engagement with context
intact.

---

# Milestone 3 — Complete the web-recon surface

**Status: QUEUED**

Now that the product can handle common targets and findings, finish the major web
surface before vulnerability automation.

## 3.1 Historical URL intelligence

Integrate a bounded passive historical URL provider such as gau and/or waybackurls.

Requirements:

- archived URLs are clearly marked as historical observations;
- they are not treated as proof that an endpoint is currently live;
- provider provenance is retained;
- no automatic active probing of every historical URL;
- deduplication integrates with current URL assets.

## 3.2 JavaScript inventory and static analysis

Build a conservative static JS-analysis path:

- collect script URLs from authorized pages/evidence;
- retain script metadata;
- extract URL/API route candidates;
- identify source-map references;
- record interesting static observations with provenance.

Do not turn the first version into an automatic secret-harvesting or exploit system.

## 3.3 API discovery

Add explicit discovery/analysis for common API descriptions and surfaces:

- OpenAPI / Swagger documents;
- GraphQL endpoint indicators;
- API route candidates from current/historical/JS evidence.

Discovery is not automatic authenticated testing.

## 3.4 Screenshots

Add bounded screenshot capture for explicitly selected/in-scope web assets.

Requirements:

- screenshots become evidence/artifacts linked to assets;
- no hidden broad screenshot sweep;
- clear storage and retention behavior.

## 3.5 Content-discovery hardening

Revisit ffuf after real use:

- soft-404 / wildcard-response handling if needed;
- clearer result review;
- no automatic expansion into broader fuzzing categories.

## Exit condition

For an authorized website, MACSPLOIT can represent current crawl results, content
discovery, historical surface, JS/API leads, native HTTP metadata, and visual evidence
in one model.

---

# Milestone 4 — Vulnerability assessment

**Status: QUEUED**

Assessment begins only after the Findings model exists.

## 4.1 Findings engine hardening

Add:

- deterministic deduplication/correlation;
- multiple evidence references;
- confidence updates across repeated observations;
- provider attribution;
- false-positive/retest workflow.

## 4.2 TLS analysis

Implement native or provider-backed TLS/certificate assessment with evidence-first
normalization.

Examples of the category include:

- certificate metadata;
- validity/hostname issues;
- protocol/cipher observations where safely bounded;
- certificate relationships.

## 4.3 Conservative Nuclei integration

Add a detection-oriented Nuclei provider.

Requirements:

- explicit analyst launch;
- conservative template policy;
- template identity/version recorded;
- bounded concurrency/time;
- findings preserve severity and confidence separately;
- evidence is retained;
- no automatic exploitation chain.

## 4.4 Native analyzer → finding rules

Where appropriate, allow existing Native HTTP/TLS observations to create reviewable
findings without pretending every absent header is automatically a vulnerability.

## 4.5 Service/CVE enrichment

If service fingerprints are enriched with CVE/product intelligence:

- treat fingerprint matching as uncertain;
- preserve version/source evidence;
- never claim exploitability solely from a banner match.

## Exit condition

MACSPLOIT produces evidence-backed, reviewable findings from native analysis and
conservative assessment providers without automatic exploitation.

---

# Milestone 5 — Reporting and engagement export

**Status: QUEUED**

At this point the project should support a complete reconnaissance → finding → report
loop.

## 5.1 Structured export

Versioned exports for:

- JSON
- Markdown
- HTML

## 5.2 Bug bounty report output

Generate a report draft from selected findings containing:

- title;
- severity/confidence;
- affected asset;
- description;
- reproduction notes;
- evidence references;
- remediation.

The analyst remains responsible for final wording and submission.

## 5.3 Evidence bundle

Allow selected evidence/artifacts to accompany an export with clear manifest/hash
metadata.

## 5.4 Redaction and privacy review

Before broad export:

- review local paths;
- cookies/secrets;
- email/OSINT data;
- provider stderr;
- usernames;
- private workspace notes.

Exports must not blindly leak sensitive workspace material.

## 5.5 PDF later

PDF is an output layer after structured report content is stable.

## Exit condition

A bug bounty or assessment can be completed and exported from MACSPLOIT without
reconstructing the engagement manually from terminal files.

---

# Milestone 6 — OSINT

**Status: QUEUED**

OSINT begins after the core assessment workflow is coherent.

## 6.1 Username + email OSINT

**Existing issue: #22 — user-scanner integration**

Initial provider scope:

- Username targets
- Email targets
- public profile/account discoveries
- metadata/provenance
- confidence preservation
- bounded explicit execution

Initial integration excludes unrestricted recursive pivots, breach credential
collection, and evasion/proxy systems.

## 6.2 Domain OSINT

Add domain-focused public intelligence that provides meaningful information not already
covered by active recon.

Examples may include public registration/organization, certificate transparency, or
other passive sources after provider review.

## 6.3 Phone OSINT

Evaluate PhoneInfoga or another maintained provider with the same evidence/confidence
model.

## 6.4 Alternative username providers

Sherlock/Maigret are added only if they provide useful coverage or validation beyond
user-scanner. Provider count is not a roadmap goal.

## 6.5 Identity correlation

Build explicit correlation edges with confidence/provenance.

A shared username or email registration result does not automatically mean two
profiles belong to the same human.

## Exit condition

Username, email, domain, and phone research can be performed as explicit OSINT
workflows with evidence and uncertainty preserved.

---

# Milestone 7 — Local source and repository analysis

**Status: QUEUED**

Expand the local-app workflow into source-assisted assessment without requiring public
deployment.

## Scope

For an explicitly selected local repository/directory, evaluate integrations such as:

- Semgrep for static analysis;
- Gitleaks / TruffleHog for local secret detection;
- dependency/SBOM vulnerability analysis;
- framework/configuration metadata;
- mapping source paths/routes to runtime assets where confidence allows.

## Privacy rules

- source scanning is opt-in and local;
- detected secrets are redacted/minimized in persistence by default;
- no automatic upload to external services;
- a repository path is not silently widened into unrelated filesystem access.

## Exit condition

A program-provided repository can be cloned/run locally, assessed through localhost
workflows, and analyzed statically inside the same workspace with findings/evidence
correlation.

---

# Milestone 8 — Provider platform maturity + Core 1.0 candidate

**Status: QUEUED**

Only after major product categories exist should the provider boundary become a stable
extension platform.

## 8.1 Provider contract stabilization

- capability model;
- target compatibility;
- risk classes;
- setup/help metadata;
- execution/evidence contract;
- version compatibility.

## 8.2 Provider manifest / SDK

Design a documented third-party provider boundary without exposing arbitrary shell
execution as the plugin model.

## 8.3 Dependency/license metadata

Surface provider licensing, version compatibility, and external dependencies.

## 8.4 Managed installation — optional future subphase

Only after a threat-model review, consider explicit user-approved install/update
support.

No silent installation. No arbitrary remote scripts.

## 8.5 Core 1.0 release gate

A Core 1.0 candidate should have:

- stable workspace migrations;
- stable internal data model expectations;
- tested upgrade path;
- recon, findings, reports, OSINT, and local-source workflows;
- provider compatibility policy;
- documented backup/export path;
- signed/notarized distribution plan;
- strong onboarding and user documentation.

The AI, validation, hardware, and wireless roadmap does **not** need to block Core 1.0.

## Exit condition

MACSPLOIT can be treated as a coherent extensible security workbench rather than a
rapidly changing collection of internal provider adapters.

---

# Milestone 9 — AI analyst and node interface

**Status: FUTURE**

**Existing issues: #21 and #9**

Issue #15's product decision remains the governing principle: broad core security
categories come before AI implementation.

## 9.1 Node-interface design

Issue #21 may be used to design the future workflow surface, but implementation waits
for this milestone.

## 9.2 Read-only analyst first

The first AI capability should be able to:

- summarize workspace assets/evidence/findings;
- explain provider results;
- identify gaps in an assessment plan;
- draft report text;
- suggest next actions.

No active execution is required for the first AI slice.

## 9.3 Permissioned actions

Later, an agent may propose or launch MACSPLOIT workflows only through the same typed
scope/risk interfaces used by the UI.

Requirements:

- no hidden scope expansion;
- no arbitrary shell by default;
- explicit approval for active actions;
- action/audit history;
- bounded recursion;
- provider permissions;
- deterministic stop/cancel controls.

## 9.4 Model adapters

Support local and/or explicitly configured model backends without making one vendor a
hard dependency of the workbench.

## 9.5 MCP

If MCP is added, prefer a MACSPLOIT-controlled permissioned tool surface rather than
letting an AI bypass the workbench and call provider CLIs directly.

## Exit condition

AI improves analyst workflow while remaining subordinate to MACSPLOIT scope,
permissions, evidence, and audit boundaries.

---

# Milestone 10 — Authorized Validation / Lab

**Status: FUTURE**

This is separate from normal reconnaissance and assessment.

## Scope

Design an explicit validation/lab execution layer for behavior that is too invasive for
the default workbench.

Possible categories include:

- authenticated validation;
- carefully bounded proof/verification actions;
- deeper SQL injection validation if eventually added;
- controlled lab workflows;
- replay/retest helpers.

## Required separation

- separate mode/workspace signal;
- explicit analyst approval;
- stronger risk-class gates;
- clear evidence/audit trail;
- no automatic escalation from standard recon.

## Exit condition

Higher-impact validation can exist without changing the safety semantics of ordinary
MACSPLOIT reconnaissance.

---

# Milestone 11 — Infrastructure, network, cloud, and containers

**Status: FUTURE**

This milestone requires separate scope semantics because one network/cloud target can
represent many systems.

Potential areas:

- deliberate CIDR/network inventory;
- Docker/container assessment context;
- Kubernetes;
- cloud asset inventory;
- remote scanning agents;
- isolated lab targets.

A CIDR entered as scope must never silently become permission to mass scan the range.

---

# Milestone 12 — Hardware and wireless

**Status: FUTURE**

Examples include future integrations with:

- Raspberry Pi agents;
- Wi-Fi/security lab hardware;
- SDR/Bluetooth tooling;
- USB/HID lab devices.

These features require their own permission, safety, and device-trust design before
implementation. They remain separate from normal recon.

---

# Milestone 13 — Distribution and long-term release engineering

**Status: QUEUED / ongoing as release maturity requires**

Distribution work can advance when necessary without changing product milestone order.

Areas include:

- Apple code signing;
- notarization;
- packaging/installer;
- update strategy;
- migration/backup guarantees;
- compatibility matrix;
- accessibility;
- crash diagnostics that preserve the project's privacy posture;
- release notes and reproducible release procedure.

No telemetry is introduced casually.

---

# Continuous engineering tracks

These are allowed alongside the active milestone when they do not become disguised
feature work.

## Security and CI

- CodeQL
- dependency review
- identity/history audit
- secret scanning
- branch/check policy
- test reliability
- build speed

## Documentation

Documentation may be corrected whenever implementation changes. Documentation-only
work must not claim an unimplemented feature exists.

## UX and accessibility

Small usability/accessibility fixes may proceed in parallel when they do not restructure
the active feature's files or create merge conflicts.

## Performance and reliability

Profiling, crash fixes, database reliability, cancellation, and bounded-resource fixes
may interrupt roadmap order when they are genuine correctness issues.

## Community / contribution health

Issues, Discussions, examples, contribution docs, and good-first-issue work can proceed
without changing product priority.

---

# Parallel-work policy

Default: **one feature PR at a time**.

Up to two implementation PRs may run concurrently when all are true:

1. both are within the active milestone or one is continuous engineering;
2. they touch mostly separate subsystems/files;
3. neither changes the same protocol/data model in incompatible ways;
4. each has a named issue/task;
5. both start from current `main`;
6. the second PR is rebased/reconciled after the first merges;
7. neither agent is allowed to merge.

Examples of acceptable parallel work:

- provider-center UI + independent documentation/CI maintenance;
- localhost transport tests + non-overlapping Findings schema design, if explicitly
  approved.

Examples of unacceptable parallel work:

- two agents changing ReconView, ChainKind, and provider protocol independently;
- implementing a future OSINT/AI provider while the active milestone is local-target
  usability simply to consume model usage.

---

# Idea intake and reprioritization

New ideas are welcome. They do not interrupt active work automatically.

For every new idea:

1. describe the user problem;
2. identify which roadmap milestone it belongs to;
3. create or update an issue;
4. mark whether it is required, optional, or research;
5. continue the current milestone.

To intentionally reprioritize:

1. explain why the current order is wrong;
2. update this roadmap in a reviewed PR;
3. update the master roadmap issue;
4. only then assign implementation work.

---

# Owner / agent operating procedure

Before assigning Claude, Codex, or another coding agent:

1. read current `docs/roadmap.md`;
2. read current `docs/features.md`;
3. inspect open PRs;
4. inspect the issue for the next incomplete active item;
5. fetch current `main`;
6. assign a branch + PR scope;
7. state "do not merge".

After the agent finishes:

1. inspect the diff;
2. verify CI/CodeQL;
3. verify mergeability against current `main`;
4. perform manual UI acceptance when relevant;
5. merge only after owner review;
6. update issue/checklist status;
7. advance the roadmap only when the milestone exit condition is satisfied.

---

# Current issue mapping

| Issue / PR | Roadmap placement |
| --- | --- |
| PR #26 / Issue #24 — Tool Manager | Milestone 0 — DONE |
| Issue #20 — localhost/local/private targets | Milestone 1 |
| Direct IP Recon | Milestone 1 — implementation issue to create when work begins |
| Bug bounty workspace/profile | Milestone 2 — implementation issue to create when work begins |
| Findings foundation | Milestone 2 — implementation issue to create when work begins |
| Historical URLs | Milestone 3 — issue to create when active |
| JavaScript analysis | Milestone 3 — issue to create when active |
| Nuclei / TLS | Milestone 4 — issues to create when active |
| Issue #22 — user-scanner OSINT | Milestone 6 |
| Local source analysis | Milestone 7 |
| Issue #21 — AI node UI | Milestone 9 |
| Issue #9 — AI-assisted agents | Milestone 9 |
| Issue #15 — finish security categories before AI | Governing roadmap principle |
| Issue #17 — faster checks | Continuous engineering; effectively completed by optimized CI, pending close |

---

# High-level execution order

```text
M0  Consolidate current beta
    Tool Manager DONE + CodeQL cutover
            ↓
M1  Real-target usability
    localhost/private + Direct IP Recon
            ↓
M2  Bug bounty workbench + Findings foundation
            ↓
M3  Web recon completion
    historical URLs + JS + APIs + screenshots
            ↓
M4  Vulnerability assessment
    TLS + Findings engine + conservative Nuclei
            ↓
M5  Reporting and exports
            ↓
M6  OSINT
    user-scanner + domain + phone + correlation
            ↓
M7  Local source / repository analysis
            ↓
M8  Provider platform maturity + Core 1.0 candidate
            ↓
M9  AI analyst / node interface
            ↓
M10 Authorized Validation / Lab
            ↓
M11 Infrastructure / network / cloud / containers
            ↓
M12 Hardware / wireless
```

Distribution/release engineering runs as an ongoing controlled track and becomes a
formal release gate around Core 1.0.

---

## Immediate next action

Do **not** start Historical URL Intelligence yet.

The next execution sequence is:

1. verify the merged Tool Manager remains green on `main`;
2. complete the CodeQL cutover;
3. implement Issue #20 localhost/local/private targets;
4. implement Direct IP Recon;
5. complete the Milestone 1 real-target acceptance matrix;
6. only then advance to the Bug Bounty + Findings milestone.

That sequence remains authoritative until this roadmap is deliberately changed.
