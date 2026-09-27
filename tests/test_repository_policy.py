"""Offline tests using invented values and temporary Git repositories only."""

import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit", ROOT / "scripts/check_repository.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class RepositoryPolicyTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="macsploit-policy-")
        self.repo = Path(self.scratch.name)
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_NOSYSTEM="1")
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Synthetic Test")
        self.git("config", "user.email", "fixture@example.test")
        shutil.copyfile(ROOT / ".gitignore", self.repo / ".gitignore")

    def tearDown(self):
        self.scratch.cleanup()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, env=self.env,
                              capture_output=True, check=True).stdout

    def write(self, path, value):
        destination = self.repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(value)

    def check(self, mode):
        return subprocess.run(
            [os.sys.executable, str(ROOT / "scripts/check_repository.py"), mode],
            cwd=self.repo, env=self.env, capture_output=True, text=True,
        )

    def commit(self):
        self.git("commit", "-m", "Add synthetic test content")

    def test_ignore_policy_covers_sensitive_and_generated_data(self):
        cases = [
            ".DS_Store", "apps/macos/DerivedData/file", "apps/macos/.build/file",
            "app.xcodeproj/xcuserdata/user", "core/target/file", "lib/__pycache__/a.pyc",
            ".venv/bin/python", "dist/output", ".env", ".env.example", "config/dev.env",
            "config/.env.production", "config/credentials.json", "secrets.yaml",
            "cookies.txt", "tokens.json", "api_keys.json", "certs/private.pem",
            "id_ed25519", "account.keychain-db", "keychain-export.txt",
            "workspace-data/sample.json", "scanner-output/run.xml", "captures/run.json",
            "scan.pcapng", "session.har", "client.db", "state.sqlite3-wal", "reports/run.html",
        ]
        result = subprocess.run(["git", "check-ignore", "--stdin"], cwd=self.repo,
                                env=self.env, input="\n".join(cases) + "\n",
                                capture_output=True, text=True, check=True)
        self.assertEqual(set(cases), set(result.stdout.splitlines()))

    def test_source_and_lockfiles_are_trackable(self):
        for path in ["Cargo.lock", "Cargo.toml", "apps/macos/Package.swift",
                     "apps/macos/Package.resolved", "apps/macos/App.xcodeproj/project.pbxproj",
                     "core/src/evidence/mod.rs", "core/src/workspace/mod.rs",
                     "core/src/database/migrations/001.sql", "fixtures/provider/sample.json"]:
            with self.subTest(path=path):
                result = subprocess.run(["git", "check-ignore", path], cwd=self.repo,
                                        env=self.env, capture_output=True)
                self.assertEqual(result.returncode, 1)

    def test_clean_staged_documentation_passes(self):
        self.write("README.md", "Synthetic offline project for example.test.\n")
        self.git("add", ".gitignore", "README.md")
        self.assertEqual(self.check("--staged").returncode, 0)

    def test_index_is_checked_even_when_working_copy_is_clean(self):
        sample = "ghp_" + "A" * 36
        self.write("source.txt", sample)
        self.git("add", "source.txt")
        self.write("source.txt", "The working tree no longer contains the test value.")
        result = self.check("--staged")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GitHub token", result.stderr)
        self.assertNotIn(sample, result.stdout + result.stderr)

    def test_force_added_ignored_file_is_rejected(self):
        self.write(".env", "SYNTHETIC_FLAG=1\n")
        self.git("add", "-f", ".env")
        self.assertNotEqual(self.check("--staged").returncode, 0)

    def test_deleted_secret_in_history_is_still_rejected(self):
        sample = "ghp_" + "B" * 36
        self.write("sample.txt", sample)
        self.git("add", "sample.txt")
        self.commit()
        self.git("rm", "sample.txt")
        self.commit()
        result = self.check("--all-history")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GitHub token", result.stderr)
        self.assertNotIn(sample, result.stdout + result.stderr)

    def test_commit_messages_are_inspected(self):
        self.write("README.md", "Synthetic documentation")
        self.git("add", "README.md")
        self.git("commit", "-m", "ghp_" + "C" * 36)
        self.assertNotEqual(self.check("--all-history").returncode, 0)

    def test_uninspectable_blobs_are_blocked(self):
        self.assertTrue(audit.content_issues(b"binary\0payload"))
        self.assertTrue(audit.content_issues(b"\xff\xfe"))
        self.assertTrue(audit.content_issues(b"x" * (audit.MAX_BLOB_BYTES + 1)))

    def test_secret_categories_are_detected_without_storing_real_values(self):
        examples = [
            "-----BEGIN " + "PRIVATE KEY-----",
            "AKIA" + "A" * 16,
            "sk-" + "A" * 32,
            "xoxb-" + "1234567890-" * 3,
            "AIza" + "A" * 35,
            "eyJ" + "A" * 12 + "." + "B" * 12 + "." + "C" * 12,
            "Authorization: " + "Bearer " + "A" * 20,
            "Cookie: " + "session=synthetic",
            "https://" + "example:synthetic@example.test",
            "password" + " = \"" + "synthetic-value" + "\"",
        ]
        for index, value in enumerate(examples):
            with self.subTest(category=index):
                self.assertTrue(audit.content_issues(value.encode()))

    def test_private_destination_passes(self):
        metadata = dict(nameWithOwner=audit.EXPECTED_REPOSITORY,
                        isPrivate=True, visibility="PRIVATE")
        with patch.object(audit, "run", return_value=json.dumps(metadata).encode()):
            audit.verify_private_remote(f"https://github.com/{audit.EXPECTED_REPOSITORY}.git")

    def test_public_wrong_and_unverifiable_destinations_fail(self):
        remote = f"https://github.com/{audit.EXPECTED_REPOSITORY}.git"
        for metadata in [dict(nameWithOwner=audit.EXPECTED_REPOSITORY,
                              isPrivate=False, visibility="PUBLIC"), {},
                         dict(nameWithOwner="unexpected/repository",
                              isPrivate=True, visibility="PRIVATE")]:
            with patch.object(audit, "run", return_value=json.dumps(metadata).encode()):
                with self.assertRaises(RuntimeError):
                    audit.verify_private_remote(remote)
        with patch.object(audit, "run", side_effect=RuntimeError("unavailable")):
            with self.assertRaises(RuntimeError):
                audit.verify_private_remote(remote)
        with self.assertRaises(RuntimeError):
            audit.verify_private_remote("https://example.test/unapproved.git")

    def test_push_history_includes_all_reachable_commits(self):
        for number in range(2):
            self.write("README.md", f"Synthetic version {number}\n")
            self.git("add", "README.md")
            self.commit()
        head = self.git("rev-parse", "HEAD").decode().strip()
        parent = self.git("rev-parse", "HEAD^").decode().strip()
        previous = Path.cwd()
        try:
            os.chdir(self.repo)
            commits = audit.push_revisions(io.StringIO(
                f"refs/heads/main {head} refs/heads/main {parent}\n"))
        finally:
            os.chdir(previous)
        self.assertEqual(set(commits), {head, parent})


if __name__ == "__main__":
    unittest.main()
