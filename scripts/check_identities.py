#!/usr/bin/env python3
"""Audit reachable branch identities without printing rejected personal metadata."""

import json
import re
import subprocess
import sys
from pathlib import Path

HUMAN = ("doctordoomies", "doctordoomies@users.noreply.github.com")
OWNER_GITHUB = ("doctor", "160264866+doctordoomies@users.noreply.github.com")
DEPENDABOT = ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com")
GITHUB = ("GitHub", "noreply@github.com")
REVIEWED_AUTOMATION_MANIFEST = (
    Path(__file__).resolve().parent / "reviewed-automation-commits.json"
)




def load_reviewed_automation_commits():
    try:
        payload = json.loads(REVIEWED_AUTOMATION_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Reviewed automation manifest is missing or invalid") from error
    entries = payload.get("reviewed_commits")
    if not isinstance(entries, list):
        raise RuntimeError("Reviewed automation manifest must contain reviewed_commits")
    reviewed = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("Reviewed automation entries must be objects")
        sha = entry.get("sha")
        reason = entry.get("reason")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise RuntimeError("Reviewed automation commit SHA must be exact lowercase SHA-1")
        if not isinstance(reason, str) or not reason.strip():
            raise RuntimeError("Reviewed automation commits require a review reason")
        if sha in reviewed:
            raise RuntimeError("Reviewed automation manifest contains duplicate commit SHA")
        reviewed.add(sha)
    return reviewed


def git(*arguments):
    result = subprocess.run(["git", *arguments], capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError("Git failed; identity history could not be verified")
    return result.stdout.decode("utf-8")


def automated_branch(ref):
    return ref.startswith(("refs/heads/dependabot/", "refs/remotes/origin/dependabot/"))


def identity_allowed(ref, author, committer, sha=None, reviewed_automation=None):
    owner_pairs = {
        (HUMAN, HUMAN),
        (OWNER_GITHUB, OWNER_GITHUB),
        (OWNER_GITHUB, GITHUB),
    }
    if (author, committer) in owner_pairs:
        return True
    dependabot_pair = author == DEPENDABOT and committer in (DEPENDABOT, GITHUB)
    if not dependabot_pair:
        return False
    if automated_branch(ref):
        return True
    reviewed_automation = reviewed_automation or set()
    return sha in reviewed_automation


def audit():
    if git("rev-parse", "--is-shallow-repository").strip() != "false":
        raise RuntimeError("Fetch complete history before auditing identities")
    refs = []
    for line in git("for-each-ref", "--format=%(refname)%00%(symref)",
                    "refs/heads", "refs/remotes/origin", "refs/tags").splitlines():
        ref, symbolic = line.split("\0")
        if not symbolic:
            refs.append(ref)
    if not refs:
        raise RuntimeError("No branch or tag history is available to audit")
    reviewed_automation = load_reviewed_automation_commits()
    checked, automation, failures = set(), set(), set()
    for ref in refs:
        for line in git("log", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce", ref).splitlines():
            sha, author_name, author_email, committer_name, committer_email = line.split("\0")
            author, committer = (author_name, author_email), (committer_name, committer_email)
            checked.add(sha)
            if not identity_allowed(ref, author, committer, sha, reviewed_automation):
                failures.add((ref, sha))
            elif author == DEPENDABOT:
                automation.add(sha)
    for ref, sha in sorted(failures):
        print(f"BLOCKED identity: {ref} commit {sha[:12]}", file=sys.stderr)
    if failures:
        raise RuntimeError("Unapproved identity or automation branch context; do not rewrite automatically")
    print(f"Identity audit passed: {len(refs)} refs, {len(checked)} commits, "
          f"{len(automation)} trusted Dependabot commits.")


if __name__ == "__main__":
    try:
        audit()
    except (RuntimeError, OSError, ValueError) as error:
        print(f"Identity audit refused: {error}", file=sys.stderr)
        sys.exit(1)
