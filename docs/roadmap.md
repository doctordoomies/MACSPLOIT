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
- Local/private web-target support across Web Analysis, Web Recon, and Content Discovery (PR #31 / Issue #20)
- Direct IP Recon for explicitly scoped IPv4/IPv6 targets (PR #35 / Issue #33)
- CI routing + merge-gate hardening with authoritative Advanced CodeQL uploads (PR #32 / Issue #30)

## Newly completed during this roadmap review

- **Tool Manager / Provider Center — PR #26 / Issue #24**
  - merged to `main`;
  - global provider inventory;
  - status/version/path/help;
  - generic future-provider rendering;
  - copy-only setup commands;
  - no automatic installer.

## Important gaps discovered during the product review

- bug bounty program context is not modeled;
- the durable Findings foundation is merged via PR #77, and PR #89 added owner-accepted
  deterministic drafts plus run/selected-result/multi-Asset creation; GitHub-style
  discussion/comments (#78) remain;
- OSINT provider/correlation/install implementation is merged via PR #70, but M6 still
  requires the OSINT subset of #80, reliability follow-up for the owner-observed
  user-scanner failure, and the final #67 walkthrough before #58 closes;
- MACSPLOIT still has no complete vulnerability-assessment surface: TLS assessment,
  Nuclei, reviewed native Finding rules, service/CVE enrichment, and local
  source/dependency scanners remain under #68;
- the current Recon UI is still primarily preset-driven; the owner-approved #90 Linux
  terminal detour adds a flexible power-user path while plugin/workflow architecture
  remains a later platform milestone;
- reports/exports are not implemented;
- historical URLs, JavaScript analysis, API discovery, screenshots, richer network/device
  fingerprinting, and other recon depth remain planned.

These gaps define the next roadmap order.

## Owner execution lock — Linux terminal detour → OSINT exit → vulnerability completion → UI/specification polish

On 2026-10-12 the owner deliberately locked the near-term execution order around OSINT
and vulnerability completion. On 2026-10-19 the owner intentionally inserted one
bounded flexibility detour: **Issue #90 — Integrated Linux terminal**.

The revised sequence is:

1. **Complete the #90 Linux terminal foundation.**
   - This is a deliberate short detour, not a replacement for the security roadmap.
   - The first slice is an optional, explicitly set up and explicitly started Linux/Kali
     VM terminal.
   - It does not pull plugins, AI agents, visual workflows, automatic exploitation,
     wireless passthrough, or broad UI redesign forward.
2. **Resume and finish the M6 OSINT exit gate.**
   - PR #70's provider/correlation/install implementation is merged.
   - Finish the OSINT subset of #80, investigate the owner-observed user-scanner
     reliability failure, complete the #67 owner walkthrough, then close #67/#58.
3. **Then complete vulnerability scanning under #68.**
   - PR #77 delivered the durable Findings substrate.
   - PR #89 delivered deterministic Level-1 drafting and run/selected-result/multi-Asset
     Finding context.
   - Remaining work includes #78 discussion/comments, #83 TLS, #84 Nuclei, #85 reviewed
     native Finding rules, #86 service/CVE enrichment, and #87 local
     source/dependency assessment.
4. **Only after the vulnerability gate passes may broad UI perfection and specification
   polish begin.**
   - Functional UI required to run, review, cancel, and verify active work is allowed.
   - Broad visual redesign, dashboard perfection, and nonessential presentation work
     remain deferred.

This preserves the original OSINT → vulnerability direction after one explicit,
owner-approved flexibility detour.

---

# Priority detour — Integrated Linux Terminal Foundation

**Status: ACTIVE — Issue #90**

MACSPLOIT's structured providers and presets remain important, but they cannot be the
only way an advanced analyst works. This detour adds an optional real Linux terminal so
the user can run Linux security tooling directly when MACSPLOIT does not yet expose the
needed action as a first-class provider/workflow.

## First-slice direction

- dedicated Terminal section;
- explicit **Set Up Terminal** action;
- reviewed, pinned, integrity-verified Linux/Kali image acquisition;
- hardware-virtualized ARM64 guest on supported Apple Silicon Macs after a focused
  feasibility/design pass;
- persistent VM storage separate from workspaces and host-managed providers;
- VM remains stopped by default and never starts merely because MACSPLOIT launched;
- explicit **Start Terminal** / **Stop Terminal** lifecycle;
- real interactive terminal connected to the guest;
- one VM may back multiple terminal tabs/shell sessions;
- bounded, understandable CPU/RAM/disk defaults;
- clear setup/start/stop/error/progress states.

## Trust boundary

The terminal is intentionally different from a normal MACSPLOIT provider.

```text
Normal provider:
typed action → scope/risk checks → reviewed execution → Evidence/Observations

Linux terminal:
explicitly started guest → user controls arbitrary guest commands
```

Therefore the first slice must:

- clearly state that arbitrary terminal commands are user-controlled and do not inherit
  MACSPLOIT's normal typed-provider scope approval;
- never run hidden commands or scans when the VM starts;
- never give an AI agent arbitrary shell authority as part of this detour;
- never silently import terminal output into trusted normalized workspace state;
- avoid silent host-filesystem mounting or credential forwarding.

Later work may add explicit **Save as Evidence**, recognized-tool imports, plugin-provided
actions, and workflow integration, but those are not part of #90's first exit gate.

## Explicit non-goals

Do not expand #90 into:

- the public plugin marketplace/SDK;
- REA or another plugin;
- the AI node/agent system;
- a Metasploit GUI;
- automatic exploitation;
- Wi-Fi monitor mode / packet injection / hardware passthrough;
- automatic parsing of arbitrary terminal output;
- replacement of existing native Recon/OSINT providers.

## Exit condition

The owner can:

1. open Terminal while no VM is running;
2. explicitly set up the reviewed Linux environment;
3. restart MACSPLOIT without losing that environment;
4. explicitly start it and receive a usable Linux shell;
5. open multiple terminal tabs without creating multiple VMs;
6. run ordinary guest-side CLI tools;
7. stop the VM cleanly;
8. confirm it remains stopped on the next MACSPLOIT launch;
9. remove/recreate the terminal environment without deleting workspaces, Findings,
   Evidence, or host-managed providers.

Automated CI must not download a live VM image; lifecycle/integrity behavior uses mocks
or fixtures.

After this exit condition passes, development returns directly to the M6 OSINT
acceptance gate.
---

# Milestone 0 — Consolidate the current beta

**Status: DONE**

This milestone closes the current development burst before new product work starts.

## Scope

- Verify current `main` after the Tool Manager merge.
- Complete the CodeQL ownership cutover so the advanced workflow is authoritative and
  the duplicate default setup no longer runs.
- Confirm the required CI gate still behaves correctly after the cutover.
- Reconciled maintenance issue #17 ("Make Checks Faster") after PR #32 and the final
  authoritative Advanced CodeQL verification.
- Do not start a new provider merely to keep an agent busy while this gate is red.

## Exit condition

- Tool Manager remains healthy on `main`.
- Main CI is green.
- Advanced CodeQL is green and duplicate default CodeQL is disabled.
- No unresolved regression from Phase 2C or Tool Manager.
- The roadmap PR itself is merged and becomes authoritative.

---

# Milestone 1 — Real-target usability

**Status: IMPLEMENTATION MERGED via PR #61 — nonblocking follow-ups remain maintenance while OSINT is ACTIVE**

The goal is simple: common authorized targets should work directly without artificial
dependencies such as requiring public DNS first.

## 1.1 Localhost and private targets

**Issue #20 — DONE via PR #31.** Local/private web-target support is merged and verified.
Direct IP Recon (1.2) is also complete via PR #35. Milestone 1 remains active because the
owner-discovered UX stabilization pass (1.3) and the real-target acceptance matrix (1.4)
are still outstanding.

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

**Issue #33 — DONE via PR #35.** Direct IP Recon is merged to `main`, Issue #33 is
closed, and post-merge CI + authoritative Advanced CodeQL are green.

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

## 1.3 UX stabilization

**Issue #36 — DONE via PR #39.** Owner-accepted and merged. Milestone 1 remains ACTIVE;
the real-target acceptance matrix (1.5) is still outstanding. Owner testing after Direct
IP Recon exposed usability gaps that were fixed in this pass.

Required outcomes:

- Homebrew is optional and may be recommended when available, but MACSPLOIT must not
  present Homebrew as a requirement for compatible external providers.
- Existing compatible provider executables discovered through supported paths / PATH /
  explicit overrides remain first-class.
- The Rust scope boundary remains authoritative, but an out-of-scope target can be
  intentionally authorized from the Recon workflow through an explicit confirmation.
- `Authorize & Run` adds only the narrowest exact target scope entry required, persists
  it, re-checks core authorization, and then launches the selected workflow.
- Every live Run surface keeps a visible reminder that the operator must own or have
  explicit permission to assess the target.
- Recon is redesigned into a responsive workbench surface so controls are not obscured
  by the sidebar and workflow selection remains usable across supported window sizes.
- First-run setup/onboarding, including the broader authorization agreement, is a
  separate owner design discussion and is not silently added to this stabilization pass.

Do not weaken scope semantics, add broad CIDR scanning, auto-install Homebrew/providers,
or begin Milestone 2 work as part of this issue.

## 1.4 First-run setup and onboarding

**Issue #38 — DONE via PR #41.** A fresh MACSPLOIT install guides the user through
environment readiness before exposing the full workbench.

Required outcomes:

- first-run Welcome + explicit authorization-responsibility acknowledgement;
- environment check for core readiness, detected providers, versions/paths where useful,
  architecture compatibility, and optional Homebrew availability;
- provider setup that treats Homebrew as an optional recommended convenience, supports
  existing compatible executables, and never silently installs software;
- explicit optional Homebrew setup only with user approval and a reviewed current
  installation method;
- appearance/theme selection and a Standard/Advanced presentation preference;
- a simple starting dashboard preset such as Minimal, Operator, or Research;
- an optional interactive tutorial using Synthetic Recon first so the tutorial can teach
  the workbench without real network activity;
- a final Ready summary leading naturally into first workspace creation or the workbench;
- setup is resumable, re-runnable from Settings / Setup & Environment, and does not
  require deleting workspace data or preferences.

Explicit, typed installation of the reviewed provider set is implemented in the M1.4
follow-up: Homebrew for all, plus a verified app-managed direct download (pinned manifest,
HTTPS-only, SHA-256, safe extraction, atomic install) for subfinder/httpx/katana/ffuf;
Nmap is Homebrew/official only. The broader managed-provider *platform* (arbitrary
third-party providers, a marketplace, or any automatic/background updates) remains a later
provider-platform decision and is intentionally out of scope. Research/news backend
implementation is not required merely because setup can choose a Research-oriented
dashboard preset.

## 1.5 Real-target acceptance + Run Results UX

**Issue #45 — implementation merged via replacement PR #61.** PR #46 was superseded
and closed without merging. Remaining correctness/acceptance follow-ups, if still open,
stay tracked separately and do not displace the owner-locked OSINT → vulnerability order
unless they block correctness or security.

When resumed, complete the Run Results experience and maintain an acceptance matrix
covering at minimum:

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

**Status: minimum Findings substrate DONE via Issue #76 / PR #77. PR #89 then completed
the deterministic Level-1 draft flow plus run/selected-result/multi-Asset Finding
context (#79), and the owner accepted that flow. #78 discussion/comments remains.
Broader bug-bounty workspace/profile UI remains deferred. This does not mark M2/M4 or
the vulnerability-completion gate done.**

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

The minimum manual model is merged on `main` via PR #77: migration 008,
core-validated severity/confidence/lifecycle, multiple Asset/Evidence references,
durable history, shared ResultProjection and Create Finding from Recon/OSINT. See
[Findings](findings.md). Issue #76 is closed complete.

Owner testing identified two structural follow-ups before scanner-heavy work expands the
surface:

- **#79 — DONE via PR #89** — create Findings from runs/selected results/multiple
  Assets, with deterministic non-AI drafts that open the populated editor;
- **#78 — REMAINING** — GitHub-style Finding discussion timeline + analyst comments.

These are Findings hardening, not broad visual polish. TLS/Nuclei/CVE enrichment and
automated rules remain under #68.

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

**Status: DEFERRED UNTIL THE VULNERABILITY-COMPLETION GATE PASSES**

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

**Status: NEXT AFTER #90 AND THE M6 OSINT EXIT — tracked by vulnerability-completion
umbrella #68. The durable Findings prerequisite (#76 / PR #77) and #79/Level-1 draft
flow (PR #89) are complete.**

Assessment begins only after the Findings model exists.

## 4.1 Findings engine hardening

Owner-tested state:

- **#79 — DONE via PR #89** — run/selected-result/multi-Asset context and deterministic
  populated draft flow;
- **#78 — REMAINING** — unified GitHub-style discussion/comments + system-event timeline.

The merged foundation already supports multiple Asset/Evidence references, separate
severity/confidence/status, deterministic draft creation, and false-positive/retest
lifecycle. Continue hardening with:

- deterministic deduplication/correlation;
- confidence updates across repeated observations;
- provider attribution;
- reviewable comments/history.

## 4.2 TLS analysis — Issue #83

Implement native or provider-backed TLS/certificate assessment with evidence-first
normalization.

Examples of the category include:

- certificate metadata;
- validity/hostname issues;
- protocol/cipher observations where safely bounded;
- certificate relationships.

## 4.3 Conservative Nuclei integration — Issue #84

Add a detection-oriented Nuclei provider.

Requirements:

- explicit analyst launch;
- conservative template policy;
- template identity/version recorded;
- bounded concurrency/time;
- findings preserve severity and confidence separately;
- evidence is retained;
- no automatic exploitation chain.

## 4.4 Native analyzer → finding rules — Issue #85

Where appropriate, allow existing Native HTTP/TLS observations to create reviewable
findings without pretending every absent header is automatically a vulnerability.

## 4.5 Service/CVE enrichment — Issue #86

If service fingerprints are enriched with CVE/product intelligence:

- treat fingerprint matching as uncertain;
- preserve version/source evidence;
- never claim exploitability solely from a banner match.

## Vulnerability-completion gate

The project does not advance into UI/specification perfection when only one scanner
works. Before this execution block exits:

- the minimum durable Findings model required by scanners is complete;
- TLS/certificate assessment is complete;
- conservative Nuclei integration is complete;
- native HTTP/TLS analyzer observations can become reviewable findings under explicit
  rules;
- service/CVE enrichment preserves uncertainty and evidence;
- planned local source/dependency vulnerability scanning from Milestone 7 is complete
  enough for its own exit condition;
- scanner runs are explicit, bounded, cancellable, persisted, and reviewable;
- docs/features/roadmap match reality;
- CI and CodeQL are green;
- the owner completes an end-to-end vulnerability-scanning walkthrough.

## Exit condition

MACSPLOIT produces evidence-backed, reviewable findings across the planned network/web
and local-source vulnerability-scanning surfaces without automatic exploitation. Broad
UI perfection/specification work remains blocked until this condition and the linked M7
scanner gate are satisfied.

---

# Milestone 5 — Reporting and engagement export

**Status: DEFERRED UNTIL THE VULNERABILITY-COMPLETION GATE PASSES**

At this point the project should support a complete reconnaissance → finding → report
loop.

## 5.1 Structured export

Versioned exports for:

- JSON
- Markdown
- HTML

## 5.2 Bug bounty report output

**Finding/report authoring assistance is tracked by #81.** MACSPLOIT should work
out-of-the-box with deterministic structured drafts/templates; optional local or
user-configured cloud AI may improve wording but must not be required.

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

**Status: IMPLEMENTATION MERGED / OWNER ACCEPTANCE ACTIVE — Issue #58.**

PR #70 contains the Email, Phone, Domain/public-infrastructure, correlation, provider
installation, and typed result-dispatch implementation. The remaining M6 blocker is
provider-native OSINT result fidelity (#80) plus the final owner walkthrough (#67).

The immediate product goal is a coherent, evidence-first OSINT workbench covering
Username, Email, Phone, Domain/Organization, and public infrastructure/account
intelligence. Breadth is encouraged only when a provider adds distinct coverage or useful
cross-validation.

## 6.0 OSINT framework foundation

**DONE via PR #60.** The typed provider/model/UI foundation plus user-scanner
Username/Email support are merged. Issue #22 is closed complete.

## 6.1 Username + public-profile OSINT

**IMPLEMENTATION COMPLETE via PR #60 + PR #63; milestone acceptance remains under #58.**

Merged provider set:

- user-scanner — PR #60;
- Sherlock — PR #63;
- Maigret — PR #63;
- socialscan Username support — PR #63.

Cross-provider canonical deduplication preserves separate per-provider/per-run
Observations and Evidence. Matching handles remain observations, not proof of human
identity ownership.

Do not add more Username providers merely to increase provider count.

## 6.2 Email OSINT — Issue #64 — DONE

- user-scanner Email OSINT — PR #60;
- socialscan Email support — PR #70;
- Issue #64 closed complete.

Holehe was reviewed and **not integrated** because signup/reset-style account interaction
does not fit the current passive/public-source boundary.

Original focused provider wave:

- Holehe;
- socialscan Email support.

theHarvester is handled primarily by 6.4 / #66; public Email discoveries produced by
that Domain/Organization workflow should normalize into Email assets there rather than
creating a duplicate theHarvester orchestration path in #64.

Initial Email OSINT remains public registration/profile intelligence. No credential,
password, breach-secret, private-account, login, or evasion behavior.

## 6.3 Phone OSINT — Issue #65 — DONE

PR #70 merged PhoneInfoga 2.x with an explicit E.164 `PhoneNumber` target (no country
guessing), `local` + OVH public number-range scanners only. Issue #65 is closed complete.

Integrate PhoneInfoga, or a better-maintained reviewed equivalent if upstream review
shows PhoneInfoga is unsuitable.

Requirements include explicit Phone targets, normalized identifiers, bounded/cancellable
execution, structured parsing where available, evidence/provenance, restart persistence,
and no automatic pivots or interaction with the phone/account.

## 6.4 Domain / Organization / public infrastructure OSINT — Issue #66 — DONE

PR #70 merged native certificate transparency, native RDAP, and theHarvester (passive
source allow-list) on an in-scope domain; Subfinder data is reused via the shared
`Subdomain` asset type. OWASP Amass was reviewed and **not integrated** because v5 has
no enforceable passive-only mode. Issue #66 is closed complete.

Add complementary passive/public-source providers:

- theHarvester;
- OWASP Amass in passive/public-source mode;
- native RDAP / registration intelligence;
- native certificate-transparency intelligence;
- reuse existing Subfinder/provider data where it already answers the question rather
  than duplicating active Recon.

Historical/passive observations must not be represented as proof that an endpoint is
currently live. Any API configuration remains explicit and optional.

## 6.5 Correlation, aggregator review, and final acceptance — Issue #67

The implementation portion is merged via PR #70: explicit evidence-backed correlation
with review log, aggregator decision (SpiderFoot not integrated), and
acceptance/failure-semantics tests.

Completed acceptance blockers #71, #72, and #73 are closed.

**Remaining:**

- **#80 OSINT subset** — provider-native CLI-fidelity result renderers so the primary UI
  exposes at least as much useful information as each provider's normal CLI while still
  consuming typed durable state;
- final owner Username/Email/Phone/Domain + correlation walkthrough.

#58/#67 remain open until those pass.

After #64–#66:

- build/review explicit evidence-backed correlation relationships with visible
  confidence/uncertainty;
- never silently merge people/accounts from weak matching signals;
- evaluate SpiderFoot/read-only public-intelligence APIs only if they add distinct value
  and fit the existing typed architecture;
- skip aggregators that mainly duplicate coverage or require a second orchestration
  framework;
- perform the complete owner OSINT walkthrough.

## 6.6 OSINT safety and privacy boundaries

Initial OSINT is public-source research with explicit user actions and bounded providers.

Do not add as default behavior:

- credential/password collection;
- breach-password harvesting;
- exposed-secret persistence;
- private-account access;
- unrestricted recursive identity hunting;
- proxy rotation / rate-limit bypass / evasion;
- stalking/covert-surveillance workflows;
- automatic actions against discovered accounts.

Recursive pivots, if ever added, require a separate explicit design with hard
depth/result/request limits and visible provenance.

## Exit condition

Issue #58 may close only when:

- Username, Email, Phone, and Domain/Organization OSINT each have a native workflow;
- #64, #65, and #66 are complete;
- #67 correlation/acceptance is complete;
- provider readiness/version/setup is understandable;
- runs are explicit, bounded, cancellable, and durable;
- results normalize into Assets / Observations / Relationships / Evidence;
- uncertainty and provenance remain visible;
- repeat/cross-provider runs deduplicate canonical assets without losing per-run facts;
- results survive restart;
- automated tests remain offline;
- docs/features/roadmap match reality;
- CI and CodeQL are green;
- the owner completes an end-to-end OSINT walkthrough.

After #58 closes, the next allowed product phase is **#68 — vulnerability scanning
completion**. Exploitation/deeper validation remains separate, and broad UI/specification
perfection stays blocked until #68 exits.

---

# Milestone 7 — Local source and repository analysis

**Status: TRACKED BY #87 — required by vulnerability-completion umbrella #68 after
M6/M4 and before UI/specification perfection.**

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

Explicit, user-approved installation of the **reviewed provider set** is now implemented
(Homebrew, and a verified app-managed direct download for subfinder/httpx/katana/ffuf; see
`docs/providers.md`). What remains future here is any broader managed-installation *platform*
— arbitrary third-party providers, and any automatic/background update support — each of
which needs its own threat-model review first.

No silent installation. No arbitrary remote scripts. No background or automatic updates.

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

**Status: QUEUED / ongoing as release maturity requires. Zero-terminal macOS install is
tracked by #82.**

Distribution work can advance when necessary without changing product milestone order.

Owner direction: beta/source installation is acceptable while foundations are built, but
a normal macOS user should eventually install MACSPLOIT without cloning/building the
repository or using Terminal. Issue #82 tracks the signed/notarized DMG/application flow.

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

For substantial code or behavior changes, regression fixes, or work where the
current base is not already known to be green, establish a reproducible
pre-change baseline using
[baseline-verification.md](baseline-verification.md).

Small documentation-only changes can use the normal verification in
`CONTRIBUTING.md` unless CI or a maintainer requests a characterized baseline.

Do not claim a change is verified when upstream or environment failures prevent
the required checks; document those failures with evidence instead.

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
| Issue #20 — localhost/local/private targets | Milestone 1.1 — DONE via PR #31 |
| Issue #33 / PR #35 — Direct IP Recon | Milestone 1.2 — DONE |
| Issue #36 — UX stabilization | Milestone 1.3 — DONE via PR #39 |
| Issue #38 / PR #41 — first-run setup and onboarding | Milestone 1.4 — DONE |
| Issue #45 / PR #61 — Run Results + real-target acceptance | Milestone 1.5 — implementation merged; follow-ups are maintenance |
| Issue #22 / PR #60 — user-scanner Username + Email | Milestone 6 foundation/first slice — DONE; issue closed |
| PR #63 — Sherlock + Maigret + socialscan Username | Milestone 6.1 — implementation DONE |
| Issue #58 — OSINT framework and provider coverage completion | Milestone 6 — ACTIVE umbrella |
| Issue #64 — Email OSINT completion | Milestone 6.2 — DONE via PR #70; closed |
| Issue #65 — Phone OSINT | Milestone 6.3 — DONE via PR #70; closed |
| Issue #66 — Domain/Public-Infrastructure OSINT | Milestone 6.4 — DONE via PR #70; closed |
| Issue #67 — correlation + OSINT owner acceptance | Milestone 6 exit gate — implementation DONE; #80 OSINT subset + walkthrough remain |
| Issue #68 — vulnerability scanning completion umbrella | Post-M6 vulnerability block — NEXT after #58 |
| Bug bounty workspace/profile | Milestone 2 — broader product UI deferred behind vulnerability gate |
| Issue #76 / PR #77 — Findings + normalized result foundation | DONE; issue closed |
| Issue #78 — Finding discussion/comments timeline | M4.1 Findings hardening |
| Issue #79 / PR #89 — run/selected-result/multi-Asset Finding context | DONE; owner accepted |
| Issue #80 — provider-native Results UI | M6 OSINT acceptance + ongoing Recon Results UX |
| Issue #81 / PR #89 — Finding authoring assistance | deterministic Level 1 DONE; optional AI remains M5 |
| Issue #90 — on-demand managed Linux/Kali terminal | ACTIVE owner-approved priority detour |
| Issue #82 — zero-terminal signed/notarized install | M13 distribution/release hardening |
| Issue #83 — TLS/certificate assessment | M4.2 under #68 |
| Issue #84 — conservative Nuclei | M4.3 under #68 |
| Issue #85 — native observation → Finding rules | M4.4 under #68 |
| Issue #86 — service/CVE enrichment | M4.5 under #68 |
| Issue #87 — local source/dependency scanning | M7 under #68 |
| Historical URLs | Milestone 3 — deferred until vulnerability gate passes |
| JavaScript analysis | Milestone 3 — deferred until vulnerability gate passes |
| Local source analysis | Milestone 7 — part of #68 |
| Issue #21 — AI node UI | Milestone 9 |
| Issue #9 — AI-assisted agents | Milestone 9 |
| Issue #15 — finish security categories before AI | Governing roadmap principle |
| Issue #17 — faster checks | Completed / closed |

---

# High-level execution order

The milestone numbers remain stable. The owner has deliberately inserted one bounded
flexibility detour without abandoning the existing security sequence:

```text
#90 LINUX TERMINAL FOUNDATION — ACTIVE DETOUR
    optional managed Linux/Kali VM
    → explicit setup/start/stop
    → usable interactive Linux shell
    → owner terminal acceptance
            ↓
RESUME M6 OSINT EXIT (#58/#67)
    PR #70 provider/correlation/install implementation DONE
    → investigate owner-observed user-scanner failure
    → #80 OSINT provider-native Results fidelity
    → final #67 owner OSINT walkthrough
    → CLOSE #67 / #58
            ↓
#68 VULNERABILITY SCANNING COMPLETION
    #76 Findings foundation DONE via PR #77
    #79 + deterministic Level-1 drafts DONE via PR #89
    → #78 Finding discussion/comments hardening
    → #83 TLS/certificate assessment
    → #84 conservative Nuclei
    → #85 native HTTP/TLS Finding rules
    → #86 service/CVE enrichment
    → #87 local source/dependency assessment
    → owner vulnerability-scanning acceptance
            ↓
    CLOSE #68 / OWNER VULNERABILITY EXIT GATE
            ↓
REPORTING / OPTIONAL AI AUTHORING / BROAD UI PERFECTION
    #81 optional local/cloud writing assistance
    broad visual/dashboard/specification refinement
```

The terminal detour exists to restore power-user flexibility now; it does not move the
plugin platform, REA, AI agents, visual workflow editor, or authorized-validation work
ahead of their roadmap gates.

The **Recon** portion of #80 may continue as low-conflict Results UX after the OSINT
subset clears M6; it does not by itself delay #83 once #58 is closed.

Issue #82 remains deferred/controlled release engineering and does not change product
milestone order.

M3, M5, and other queued/future categories do not jump ahead of #68 unless the owner
deliberately reprioritizes this roadmap again. Functional UI necessary to operate and
verify active work remains allowed.

Distribution/release engineering remains an ongoing controlled track.

---
## Immediate next action

1. Implement and owner-test **#90 — Integrated Linux terminal foundation**. Keep the
   first slice tightly bounded to setup/start/stop + a usable guest terminal.
2. Immediately resume M6 acceptance by investigating the **owner-observed user-scanner
   failure** and finishing the **OSINT subset of #80** with provider-native,
   CLI-inspired views backed by durable normalized state.
3. Complete the final owner walkthrough in **#67** and close **#58**.
4. Begin **#68** with the remaining **#78** Findings discussion/comments hardening.
   (#79 and deterministic Level-1 drafting are already done via PR #89.)
5. Implement **#83 TLS**, then **#84 Nuclei**, **#85 native Finding rules**, **#86
   service/CVE enrichment**, and **#87 local-source/dependency assessment**.
6. Complete the #68 owner vulnerability-scanning walkthrough.
7. After the vulnerability gate, advance reporting/authoring work including the optional
   AI portion of **#81** and broader UI/specification perfection.
8. Keep **#82** as deferred release hardening until core functionality is ready for a
   normal-user distribution pass.

PR #70, PR #77, and PR #89 are merged. Issues #64, #65, #66, #71, #72, #73, and #76
are closed. #90 is the only intentional near-term detour before the M6 exit work resumes.
