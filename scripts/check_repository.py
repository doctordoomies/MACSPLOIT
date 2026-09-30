#!/usr/bin/env python3
"""Conservative local Git audit. Reports rule names, never matched secrets."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


EXPECTED_REPOSITORY = "doctordoomies/MACSPLOIT"
MAX_BLOB_BYTES = 2 * 1024 * 1024
ALLOWED_REMOTES = {
    f"https://github.com/{EXPECTED_REPOSITORY}.git",
    f"https://github.com/{EXPECTED_REPOSITORY}",
    f"git@github.com:{EXPECTED_REPOSITORY}.git",
    f"ssh://git@github.com/{EXPECTED_REPOSITORY}.git",
}
PRIVATE_ROOTS = {
    "data", "local", "private", "workspaces", "workspace-data", "assessments",
    "scanner-output", "scan-results", "scans", "captures", "evidence", "reports",
    "logs", "artifacts", "managed-tools", "wordlists", "work", "tmp", "outputs",
}
SENSITIVE_NAME = re.compile(
    r"(?i)(^\.env(?:$|\.)|\.env(?:$|\.)|^\.envrc$|"
    r"^(?:credentials|secrets|api[_-]keys|tokens|cookies|passwords)(?:$|\.)|"
    r"(?:credentials|client_secret|service-account).*\.json$|"
    r"^id_(?:rsa|dsa|ecdsa|ed25519)|^keychain-export|"
    r"^\.(?:netrc|npmrc|pypirc|git-credentials)$|"
    r"\.(?:pem|key|p12|pfx|p8|jks|keystore|keychain(?:-db)?|"
    r"pcap|pcapng|cap|har|nmap|gnmap|nessus|burp|sarif|"
    r"sqlite3?(?:-.*)?|db(?:-.*)?|mdb|rdb)$)"
)
SECRET_RULES = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "cloud access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "API token": re.compile(r"\bsk-(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{20,}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "Google API key": re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "authorization header": re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9+/_.=-]{12,}"),
    "cookie header": re.compile(r"(?im)^\s*(?:set-cookie|cookie)\s*:\s*\S+=\S+"),
    "credential in URL": re.compile(r"(?i)\b(?:https?|ftp|postgres(?:ql)?|mysql)://[^\s/:@]+:[^\s/@]+@"),
    "literal secret assignment": re.compile(
        r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|"
        r"auth[_-]?token|password|passwd|secret|token)[\"']?\s*[:=]\s*[\"'][^\"'\r\n]{8,}[\"']"
    ),
}


def run(*args, input_bytes=None):
    result = subprocess.run(args, input=input_bytes, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        # Deliberately do not echo tool output: it can contain private material.
        raise RuntimeError(f"{args[0]} failed; audit cannot verify this operation")
    return result.stdout


def content_issues(data):
    if len(data) > MAX_BLOB_BYTES:
        return ["oversized file requires explicit review"]
    if b"\0" in data:
        return ["binary data requires explicit review"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ["non-UTF-8 data requires explicit review"]
    return [name for name, pattern in SECRET_RULES.items() if pattern.search(text)]


def sensitive_path(path):
    parts = Path(path).parts
    return bool(parts and (parts[0] in PRIVATE_ROOTS or
                           any(SENSITIVE_NAME.search(part) for part in parts)))


def entries(revision=None):
    if revision is None:
        raw = run("git", "ls-files", "--stage", "-z")
    else:
        raw = run("git", "ls-tree", "-r", "-z", revision)
    result = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        fields = meta.decode("ascii").split()
        if revision is None:
            mode, oid, stage = fields
            if stage != "0":
                raise RuntimeError("Resolve merge conflicts before auditing")
        else:
            mode, _, oid = fields
        result.append((mode, oid, path.decode("utf-8")))
    return result


def ignored_paths(paths):
    if not paths:
        return set()
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "-z", "--stdin"],
        input=b"\0".join(p.encode("utf-8") for p in paths) + b"\0",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("Unable to check ignored paths")
    return {p.decode("utf-8") for p in result.stdout.split(b"\0") if p}


def audit_snapshots(revisions):
    failures = set()
    checked = set()
    for revision in revisions:
        if revision is not None:
            message = run("git", "show", "--no-patch", "--format=%B", revision)
            for issue in content_issues(message):
                failures.add((f"commit {revision[:12]} message", issue))
        snapshot = entries(revision)
        ignored = ignored_paths([path for _, _, path in snapshot])
        for mode, oid, path in snapshot:
            if (oid, path, mode) in checked:
                continue
            checked.add((oid, path, mode))
            if sensitive_path(path) or path in ignored:
                failures.add((path, "prohibited or ignored path"))
            if mode not in ("100644", "100755"):
                failures.add((path, "symlink or submodule requires explicit review"))
                continue
            size = int(run("git", "cat-file", "-s", oid))
            if size > MAX_BLOB_BYTES:
                failures.add((path, "oversized file requires explicit review"))
                continue
            for issue in content_issues(run("git", "cat-file", "blob", oid)):
                failures.add((path, issue))
    for path, issue in sorted(failures):
        print(f"BLOCKED {json.dumps(path)}: {issue}", file=sys.stderr)
    if failures:
        raise RuntimeError("Repository audit failed. Fix the data; do not bypass the check.")
    print(f"Repository audit passed: {len(checked)} file versions checked.")


def release_allows_public():
    """Whether the owner has intentionally opted into a public destination.

    Defaults to False (require PRIVATE) so the project cannot become public by
    accident. The owner flips this to true in a deliberate, reviewable commit as
    part of launch; the destination and secret/sensitive-data checks below still
    apply either way. See docs/releases/v0.1.0.md.
    """
    policy = Path(__file__).resolve().parent / "release-policy.json"
    try:
        return bool(json.loads(policy.read_text()).get("allow_public") is True)
    except (OSError, ValueError):
        return False


def verify_private_remote(remote_url):
    # Always verify the canonical destination and reject unexpected/former remotes.
    if remote_url not in ALLOWED_REMOTES:
        raise RuntimeError("Push destination is not the approved MACSPLOIT repository")
    metadata = json.loads(run("gh", "repo", "view", EXPECTED_REPOSITORY,
                              "--json", "nameWithOwner,isPrivate,visibility"))
    if metadata.get("nameWithOwner") != EXPECTED_REPOSITORY:
        raise RuntimeError("Destination is not the canonical repository; push refused")
    # Require PRIVATE unless the owner has intentionally launched (allow_public).
    if not release_allows_public():
        if (metadata.get("isPrivate") is not True or
                metadata.get("visibility") != "PRIVATE"):
            raise RuntimeError("Destination is not verified PRIVATE; push refused")


def push_revisions(stream):
    commits = set()
    for line in stream:
        fields = line.split()
        if len(fields) != 4:
            raise RuntimeError("Malformed pre-push input")
        _, local_sha, _, remote_sha = fields
        if not all(re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", sha)
                   for sha in (local_sha, remote_sha)):
            raise RuntimeError("Invalid commit ID in pre-push input")
        if set(local_sha) == {"0"}:
            continue
        object_type = run("git", "cat-file", "-t", local_sha).strip()
        if object_type != b"commit":
            raise RuntimeError("Push audit currently supports commit refs only")
        # Scanning complete reachable history also catches data removed later.
        commits.update(run("git", "rev-list", local_sha).decode().splitlines())
    return sorted(commits)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--all-history", action="store_true")
    mode.add_argument("--pre-push", nargs=2, metavar=("REMOTE_NAME", "REMOTE_URL"))
    args = parser.parse_args()
    try:
        if args.pre_push:
            verify_private_remote(args.pre_push[1])
            revisions = push_revisions(sys.stdin)
        elif args.staged:
            revisions = [None]
        else:
            revisions = run("git", "rev-list", "--all").decode().splitlines()
        audit_snapshots(revisions)
    except (RuntimeError, OSError, ValueError) as error:
        print(f"Audit refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
