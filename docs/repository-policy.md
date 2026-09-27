# Private repository policy

The sole approved remote is `https://github.com/doctordoomies/MACSPLOIT.git` (or its
equivalent GitHub SSH URL). Visibility must remain **PRIVATE**. Publishing a
release, enabling Pages, adding collaborators, or changing visibility requires
the owner's explicit approval. No public license or distribution grant has been
selected.

The canonical GitHub owner is `doctordoomies`. Both the supplied remote URL and
GitHub's repository metadata must identify `doctordoomies/MACSPLOIT`. Every other
owner is rejected, including former-owner URLs that GitHub may redirect. Keep
the identity pinned in the audit and its tests; changing ownership requires an
explicit instruction from the owner. Rejection-only test fixtures do not grant
approval to the destinations they exercise.

## Data that never belongs in Git

API keys, passwords, tokens, session cookies, credentials, private keys, Keychain
exports, environment files, real assessment data, scanner captures containing
sensitive information, local databases, and user workspace files are prohibited.
The private repository is still not a secret store or assessment archive.

Use macOS Keychain for future application credentials. Store future runtime
workspaces under `~/Library/Application Support/MACSPLOIT/`, caches under
`~/Library/Caches/MACSPLOIT/`, and logs under `~/Library/Logs/MACSPLOIT/`.
These locations are design decisions; repository setup does not create them.

Only synthetic data belongs in `fixtures/`. Prefer `example.test` and reserved
documentation IP ranges. A real response with its hostname removed is not
automatically a safe fixture. Review content, headers, identifiers, paths,
screenshots, and embedded strings before adding any sample.

## Before every commit and push

1. Review the staged diff and every outgoing commit, including deletions from
   earlier commits that may still be in history. Confirm all fixtures are synthetic.
2. Run `python3 scripts/check_repository.py --staged` before committing.
3. Run `python3 scripts/check_repository.py --all-history` before pushing.
4. Verify the GitHub destination remains private. The installed pre-push hook
   repeats this online check and audits each outgoing commit snapshot.
5. Push only after all checks pass. Never use `--no-verify` to bypass a failure.

`./scripts/setup-hooks.sh` activates tracked hooks in each local clone. Git does
not automatically install hooks on clone. The pre-commit hook inspects staged
blobs; the pre-push hook inspects the history being pushed, even if a sensitive
file was removed in a later commit. It refuses unexpected remotes, public or
unverifiable destinations, ignored paths, likely secret literals, and files it
cannot inspect as bounded UTF-8 text. Binary assets need an explicitly reviewed
policy change before they can be committed.

The audit is deliberately conservative, but it cannot prove that arbitrary text
contains no secrets or private assessment details. Review remains mandatory.
The `.gitignore` cannot protect files already tracked, and hooks can be locally
disabled; neither is a server-enforced policy. No GitHub organization policy,
branch rule, or paid security feature is assumed to be active.

If a check fails, remove the data from staging or outgoing history and rerun it.
If a real secret has been exposed, revoke or rotate it through its issuing
service; deletion alone does not undo exposure. Coordinate any history rewrite
with the repository owner.
