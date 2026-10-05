# Baseline verification procedure

This procedure strengthens Roadmap v2 verification by making it clear when a
pre-change baseline is useful and how to document it.

It is intended for substantial code or behavior changes, regression fixes, and
work where the current baseline is not already known to be green. Small
documentation-only changes can use the normal verification required by
`CONTRIBUTING.md` unless CI or a maintainer requests a characterized baseline.

## Procedure

1. **Start from a clean, known base.** Use a fresh checkout or a clean worktree
   at the target branch or base commit. Do not characterize a baseline on top of
   unrelated uncommitted changes.

```sh
git clone https://github.com/doctordoomies/MACSPLOIT.git
cd MACSPLOIT
git checkout <base-commit-for-the-change>
git status   # must be clean
```

2. **Install dependencies exactly per lockfile.** Do not float dependency
   versions while establishing the baseline.

```sh
cargo fetch --locked
```

   Swift and Python checks use the system toolchains documented in
   `docs/development.md` and `CONTRIBUTING.md`. When a baseline log is required,
   record the relevant toolchain versions with it.

3. **Capture a pre-change baseline when it is materially useful.**

   A full pre-change baseline is expected for:

   - substantial code or behavior changes;
   - regression fixes;
   - changes where the current base is not already known to be green;
   - work where a maintainer specifically requests baseline characterization.

```sh
./scripts/test.sh 2>&1 | tee baseline.log
```

   For a small documentation-only change on a known-green base, a separate
   pre-change full-suite run is optional. The PR should still complete the normal
   required verification before merge.

4. **Triage baseline failures.** Classify each failure as:

   - **environment issue** — fix or pin the environment cause and re-run;
   - **flaky test** — re-run to confirm and document the flake;
   - **genuine pre-existing bug** — file or link an issue and do not silently
     include the fix in unrelated work.

   If the baseline is not green, document the exact failing set and why it is
   pre-existing before claiming the new change is verified.

5. **Apply the change in isolation** on a dedicated branch, keeping the diff
   minimal and scoped to the assigned issue or task.

6. **Run post-change verification.**

   For substantial code or behavior changes, run the full suite and capture the
   result when useful:

```sh
./scripts/test.sh 2>&1 | tee post-change.log
```

   For small documentation-only changes, follow the normal checks in
   `CONTRIBUTING.md` and rely on CI unless a maintainer requests additional
   verification.

7. **Summarize the result.**

   When a pre-change baseline was captured, state what changed between the
   baseline and post-change verification and confirm that no previously passing
   check regressed.

## PR evidence

When this baseline procedure is used, include enough evidence in the PR for a
maintainer to understand and reproduce the result.

Useful evidence may include:

- baseline and post-change logs;
- CI links;
- a concise before/after summary;
- exact reproduction commands;
- relevant toolchain versions.

Full log attachments are not required for trivial changes unless specifically
requested.

## Escalation

If verification cannot be completed because of upstream or environment
breakage, do **not** claim the change is fully verified.

Document the exact failing set with evidence and mark the work
**BLOCKED_UPSTREAM** when appropriate.
