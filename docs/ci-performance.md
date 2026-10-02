# CI routing, performance, and CodeQL cutover

The optimization keeps policy checks on every run and makes expensive jobs depend
on a tested, conservative classifier. Application behavior is unchanged. The
required check remains exactly **Build & test (macOS)**.

## Measured baseline

Measured from GitHub job/step timestamps on 2026-10-02 UTC (queue and execution are
separate; step durations need not sum to wall time):

| Run | Measurement |
| --- | --- |
| [README PR CI](https://github.com/doctordoomies/MACSPLOIT/actions/runs/36949203054) | 24 seconds total |
| [README PR default CodeQL](https://github.com/doctordoomies/MACSPLOIT/actions/runs/36949200283) | 880 seconds total; Swift queue 6s + execution 871s; autobuild 746s, analysis 69s |
| Same CodeQL run, Rust | Queue 1s + execution 265s; analysis 215s |
| Same CodeQL run, Python / Actions | 45s / 33s including queue |
| [Feature PR CI](https://github.com/doctordoomies/MACSPLOIT/actions/runs/36947546139) | Swift queue 126s + execution 66s; Rust queue 202s + execution 51s |
| Same feature run, caches | Swift restore 9s; Rust restore 11s |
| [README merge on main](https://github.com/doctordoomies/MACSPLOIT/actions/runs/36951095145) | macOS queue 7s + execution 82s; Cargo restore 21s; full suite 41s; app packaging/build 6s |

These are observed baselines, not guarantees. Updated measurements and any
remaining validation limits are recorded in the optimization PR.

## Routing

Both workflows run their lightweight router on Ubuntu. There are no workflow-level
path exclusions that could leave required checks pending. `classify_ci_changes.py`
reads event JSON, validates commit SHAs, and uses a NUL-delimited Git diff with rename
detection disabled so both deleted and added paths count. PRs compare base/head;
main pushes compare before/after, not just the final commit of a multi-commit push.
Missing/zero/unavailable SHAs, forced/non-ancestor pushes, invalid paths, empty
changes, unknown events/paths, and executable/symlink documentation request full
coverage. No shell interpolation of event values is used.

| Change/event | Normal CI | Advanced CodeQL |
| --- | --- | --- |
| README / approved docs or artwork paths, PR or main | Ubuntu policy + required gate | Router + security gate; all analyzers intentionally skipped |
| Rust-only PR, Cargo/lock/toolchain/build-core | Full Rust suite, format and Clippy on Ubuntu | Rust, no build |
| Swift-only PR, Swift package/resources/build scripts | macOS Swift tests with actual Rust helper/offline bridge + signed app build | Swift manual production build |
| Mixed Rust + Swift PR | Ubuntu Rust + complete macOS suite | Rust + Swift |
| Policy Python/tests/manifests | Ubuntu policy/routing tests and full-history audits | Python |
| Schemas, providers, fixtures, shared test scripts, classifier/gates, workflow/action configuration | Ubuntu Rust + full macOS suite + policy | All four languages |
| Main application-code push | Full macOS suite + policy; also Ubuntu Rust when Rust changed | Affected languages |
| Unknown/unreliable classification | All CI jobs appropriate to full mode | All four languages |
| `release/**` push / manual full verification | Full Linux Rust + macOS suite + policy | All four languages |
| Weekly security schedule | Separate from normal CI | All four languages, regardless of paths |

Rust source tests, including process supervision, scope, evidence, persistence, and
provider fixtures, execute unmodified on Ubuntu. Full macOS Rust/Swift integration
remains mandatory on code pushes to main, mixed/shared PR changes, release branches,
and manual verification. Swift-only CI uses `test-swift.sh`, extracted unchanged
from the full suite, so fake Subfinder/Nmap/HTTPX/Katana, static DNS, and the Web
Analysis fixture cannot drift between jobs. No scanner is installed or invoked by
CI; dependency downloads are distinct from testing provider behavior.

`check_ci_gate.py` validates all routing booleans and requires success for each
selected job. It requires `skipped` only for jobs explicitly excluded by the router.
A failed router, missing output, cancellation, or unexpected skip fails the gate.
The CodeQL equivalent is **Security analysis**. No branch-protection setting is
changed by this PR.

## Build and cache decisions

Swift CodeQL initializes its extractor **before** running
`./scripts/swift-command.sh build --product MACSPLOIT`. That product depends on
MACSPLOITKit, covering both production targets without running tests or compiling
Rust. SwiftPM builds the runner's native architecture; `uname -m` and Swift version
are recorded. No architecture is hard-coded. There is no restored Swift build
cache that could hide compilation from CodeQL. The regular Swift build also has
no cache: this package has no external Swift dependencies, and adding transfer and
cache invalidation overhead is not justified by current measurements.

Rust CodeQL uses `build-mode: none`, the supported Rust extraction mode. Python and
Actions likewise need no build. Jobs have explicit timeouts: policy 10m, Linux
Rust/Swift CI 25m, full macOS 35m, Swift CodeQL 30m, other CodeQL 20m, gates/router 5m.

Cargo retains registry/git/target caching rather than assuming that deleting a
9–21s restore is a net saving. Keys now include OS, architecture, a `rustc -vV`
digest, lockfile hash, and a new cache namespace. There are no broad restore-key
fallbacks. Only successful main pushes save caches; PRs only restore. Standard
GitHub cache ref isolation applies. This avoids writing a cache for every PR and
keeps Linux/macOS/compiler artifacts separate. Any future registry-only/no-target
switch should compare cold/warm timings on the same runner and compiler first.

A local macOS arm64 comparison (same source and compiler, Clippy followed by all
Rust tests, 2026-10-02) measured **8.01s warm target**, **16.14s registry-only**
(fresh target directory), and **20.01s no-cache** (fresh target and Cargo home).
These local figures exclude GitHub cache transfer/runner queue and are not hosted
speedup claims. They show that dropping target/registry reuse adds real compilation
and download work; the PR's cold Ubuntu run supplies the portability baseline.
Incremental helper build measured **3.87s**, Swift production build **0.71s**.
The existing hosted app build/packaging step was only **6–8s**. No skip mode or
Swift artifact cache is justified by those measurements.

`build-core.sh` is deliberately retained in both testing and packaging. Cargo's
incremental freshness check is cheap and prevents packaging a stale helper. There
is no skip-build switch. Repeated commands alone are not evidence of costly
recompilation.

## Owner action required: CodeQL advanced setup cutover

Inspection confirmed **default setup configured** for Actions, Python, Rust, and
Swift, with the default query suite and weekly schedule. Main requires only
`Build & test (macOS)` (GitHub Actions app 15368); there are no repository rulesets.
No CodeQL required-check migration is currently necessary. Require the stable
**Security analysis** gate only after verifying a successful authoritative run;
that settings change is an owner decision.

1. Review the optimization PR's complete CI and all four advanced analyzer results.
   Before cutover, `MACSPLOIT_CODEQL_ADVANCED` is absent/false: advanced analysis is
   a **rehearsal**, with both SARIF and database uploads disabled. Existing default
   CodeQL remains authoritative. Temporary duplicate computation during this
   validation is expected; it is not the final deployment state.
2. Merge only with owner approval. In the same maintenance session, visit
   **Repository → Settings → Code security / Advanced Security → CodeQL analysis →
   Switch to advanced / disable default setup**. Do not delete the new workflow.
   If the UI generates another workflow, do not retain a competing copy.
3. Under **Settings → Secrets and variables → Actions → Variables**, set repository
   variable **MACSPLOIT_CODEQL_ADVANCED** to the literal `true`. This enables SARIF
   and database uploads in the reviewed advanced workflow.
4. Immediately use **Actions → CodeQL advanced → Run workflow → main**. This manual
   run selects every language. Confirm all analyzers and **Security analysis** pass;
   analyzer steps wait for uploaded SARIF processing. In Security → Code scanning,
   verify fresh results for `main` and each `/language:rust`, `/language:swift`,
   `/language:python`, `/language:actions` category from `.github/workflows/codeql.yml`.
   Check that Swift extraction includes both production targets (no missing-source
   diagnostics); review analysis warnings and coverage, not just green checkmarks.
5. Confirm the default-setup API reports `not-configured`, no new
   `dynamic/github-code-scanning/codeql` runs appear, and only the advanced workflow
   is scheduled. Historical default analyses may remain for reference; do not
   delete alerts merely to tidy configuration. Cancel obsolete default runs only
   once the replacement run is verified.
6. Open a small docs-only PR to verify policy and both gates complete without a
   macOS job or language analysis. Push two commits to a code PR and confirm the
   older **advanced** run is cancelled. Manual/scheduled scans have independent
   concurrency groups so PR edits do not cancel the full security fallback.

No settings or repository variables are changed by the implementation task.
Do not leave default disabled while upload mode is still rehearsal. If you cannot
complete steps 2–4 promptly, keep default setup enabled and postpone cutover.

### Safe rollback

If the authoritative advanced scan fails, immediately restore default setup for
all four languages and verify a successful default scan. Set the advanced variable
to `false` and disable the advanced workflow (or revert it) to avoid competing
uploads. Do not delete historical alerts. Revert the CI workflow/script changes
through review if routing is faulty; manual normal CI always requests the full
suite while a fix is prepared. Keep `Build & test (macOS)` required throughout.

## Dependabot: review before merge

Do not expand identity exceptions. Before merging a dependency PR that retains
bot-authored commits, inspect its **current exact commit SHAs**, GitHub account,
verified signature context, and diff. Explicitly reviewed SHAs with exact trusted
identity pairs must be added to `reviewed-automation-commits.json` **before** the
merge, with a reason and source PR. Re-review if Dependabot rebases and changes the
SHA. Prefer including the reviewed manifest change on that PR and verifying the
prospective main merge in a temporary local branch with `check_identities.py`.
Do not rely on GitHub's squash UI to produce a canonical human author: inspect
its actual metadata. Never rewrite bot history to masquerade as human work or
automatically approve commits by display name. A separate review helper can be
proposed later; this optimization does not change identity policy or manifests.

## References

- [GitHub CodeQL build modes](https://docs.github.com/en/code-security/reference/code-scanning/codeql/build-options-for-compiled-languages)
- [CodeQL action and supported v4 usage](https://github.com/github/codeql-action)
- [Analyze upload controls](https://github.com/github/codeql-action/blob/main/analyze/action.yml)
- [Repository policy](repository-policy.md)
