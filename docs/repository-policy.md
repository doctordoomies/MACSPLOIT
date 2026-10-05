# Repository and release policy

The sole approved remote is `https://github.com/doctordoomies/MACSPLOIT.git` (or its
equivalent GitHub SSH URL). The owner has explicitly authorized public launch.
`scripts/release-policy.json` records that authorization with `allow_public: true`;
without that explicit opt-in the audit requires PRIVATE. Canonical-destination,
secret, sensitive-data, and history checks always remain active. Apache-2.0 is the
selected license. Adding collaborators, Pages, tags, or a GitHub Release is not
part of this public-visibility authorization.

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
3. Run `python3 scripts/check_repository.py --all-history` before pushing when you want a deliberate repository-wide audit. CI uses `--reachable-history HEAD` so an unrelated in-progress branch cannot make another PR fail.
4. Verify canonical GitHub destination and intended visibility. The installed pre-push hook
   repeats this online check and audits each outgoing commit snapshot.
5. Push only after all checks pass. Never use `--no-verify` to bypass a failure.

`./scripts/setup-hooks.sh` activates tracked hooks in each local clone. Git does
not automatically install hooks on clone. The pre-commit hook inspects staged
blobs; the pre-push hook inspects the history being pushed, even if a sensitive
file was removed in a later commit. It refuses unexpected or unverifiable remotes, public destinations without the
owner opt-in, ignored paths, likely secret literals, and files it
cannot inspect as bounded UTF-8 text. Binary assets require an explicit entry in `scripts/reviewed-assets.json` with the exact repository path, SHA-256 checksum, and review reason. The audit permits only the pinned bytes; replacing an approved binary requires a new review and checksum.

The audit is deliberately conservative, but it cannot prove that arbitrary text
contains no secrets or private assessment details. Review remains mandatory.
The `.gitignore` cannot protect files already tracked, and hooks can be locally
disabled; neither is a server-enforced policy. No GitHub organization policy,
branch rule, or paid security feature is assumed to be active.

If a check fails, remove the data from staging or outgoing history and rerun it.
If a real secret has been exposed, revoke or rotate it through its issuing
service; deletion alone does not undo exposure. Coordinate any history rewrite
with the repository owner.

## Reachable identity verification

Run `python3 scripts/check_identities.py` after fetching current origin branches.
The complete test suite also runs this release check. It checks every commit
reachable from local branches, origin branches, and tags, rejects shallow history,
and prints only ref/commit locations for failures rather than private identities.

Owner-authored commits must match one of these exact pairs:

- Canonical local/API identity: author and committer are both
  `doctordoomies <doctordoomies@users.noreply.github.com>`.
- GitHub API identity: author and committer are both
  `doctor <160264866+doctordoomies@users.noreply.github.com>`.
- GitHub web identity: author is
  `doctor <160264866+doctordoomies@users.noreply.github.com>` and committer is
  `GitHub <noreply@github.com>`.

Dependabot receives a narrow trusted automation exception:

- On local/origin `dependabot/*` branches, the exact Dependabot author identity is
  allowed with either the exact Dependabot committer identity or
  `GitHub <noreply@github.com>`.
- If a reviewed Dependabot commit is retained in human-branch history after a merge,
  that exact commit SHA must be pinned in
  `scripts/reviewed-automation-commits.json` with a non-empty review reason.
  Only the pinned SHA plus the exact Dependabot/GitHub identity pair is accepted.

No name-only, email-domain, arbitrary-bot, or wildcard Dependabot-on-main
exception exists. Ordinary external human contributors are allowed, including
GitHub-web commits where GitHub is the committer. Owner identities remain pinned
to the exact approved pairs above so legacy or mixed owner metadata cannot be
smuggled through as an external contributor. Git metadata alone does not
authenticate a bot; review the GitHub PR/account/signature context before adding
a SHA to the automation manifest. Replacing the SHA requires a new review. Do not
rewrite trusted automation or contributor commits into owner identities.

Prefer squash-merging future Dependabot PRs into a canonical owner-authored commit
so bot commits do not normally enter human-branch history. The reviewed-automation
manifest is for exceptional retained commits, not a general automation bypass. CI
audits branch refs; ephemeral GitHub PR test-merge refs are not published branch
history.
