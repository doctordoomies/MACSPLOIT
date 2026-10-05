# Baseline verification procedure

*This document outlines the verification steps for changes affecting the roadmap or milestone tracker.*

Issue #27 requires that any change to the roadmap or milestone tracker be
verifiable against a characterized baseline. A fix is **unverifiable by
definition** if the test suite was already failing before the change was applied.

Every agent PR that touches roadmap/tracker files (or any code) must follow this
procedure and attach the artifacts to the PR.

## Procedure

1. **Clean baseline.** From a fresh checkout of the target branch at the base
   commit (do not build on top of uncommitted local state):

      git clone git@github.com:doctordoomies/MACSPLOIT.git
   cd MACSPLOIT
   git checkout <base-commit-for-the-issue>
   git status   # must be clean
   
2. **Install dependencies exactly per lockfile.** No floating versions:

      cargo fetch --locked
   
   Swift and Python checks use the system toolchains documented in
   `docs/development.md` and `CONTRIBUTING.md`; record `swift --version` and
   `python3 --version` in the baseline log.

3. **Capture the true baseline log** (full suite, before any change):

      ./scripts/test.sh 2>&1 | tee baseline.log
   
4. **Triage every baseline failure.** Classify each failure as:
   - **environment issue** — fix or pin the environment cause and re-run;
   - **flaky test** — re-run to confirm, note the flake;
   - **genuine pre-existing bug** — file or link an issue; do not silently fix it
     inside an unrelated PR.

   The baseline must be green, or the exact failing set must be documented in the
   PR with the triage classification.

5. **Apply the change in isolation** on a dedicated branch, keeping the diff
   minimal and scoped to the assigned issue.

6. **Re-run the full suite** and capture the post-change log:

      ./scripts/test.sh 2>&1 | tee post-change.log
   
7. **Produce a before/after diff summary** showing that no baseline-passing test
   regressed and that any newly passing test is attributable to the change.

## PR artifacts

Attach to the PR description:

- `baseline.log` (pre-change full-suite run);
- `post-change.log` (post-change full-suite run);
- the test diff summary;
- the exact reproduction commands (the commands above plus toolchain versions).

## Escalation

If the suite cannot be made green due to upstream breakage, do **not** claim the
fix is verified. Document the exact failing set with evidence in the PR and mark
the job **BLOCKED_UPSTREAM**.