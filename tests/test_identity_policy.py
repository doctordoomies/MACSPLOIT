"""Release identity rules use synthetic repositories and exact trusted pairs."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("identities", ROOT / "scripts/check_identities.py")
identities = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identities)


class IdentityPolicyTests(unittest.TestCase):
    def test_exact_owner_pairs_are_allowed_on_human_branches(self):
        allowed = (
            (identities.HUMAN, identities.HUMAN),
            (identities.OWNER_GITHUB, identities.OWNER_GITHUB),
            (identities.OWNER_GITHUB, identities.GITHUB),
        )
        for ref in ("refs/heads/main", "refs/heads/release/public-launch",
                    "refs/heads/feature/test", "refs/remotes/origin/dependabot/cargo/test"):
            for author, committer in allowed:
                self.assertTrue(identities.identity_allowed(ref, author, committer))
            self.assertFalse(identities.identity_allowed(ref, identities.HUMAN, identities.GITHUB))
            self.assertFalse(identities.identity_allowed(ref, identities.OWNER_GITHUB, identities.HUMAN))
            self.assertTrue(identities.identity_allowed(
                ref, ("Other Human", "other@example.test"),
                ("Other Human", "other@example.test")))
            self.assertFalse(identities.identity_allowed(
                ref, ("Other Human", "other@example.test"), identities.HUMAN))

    def test_exact_dependabot_pairs_only_on_automation_branches(self):
        for ref in ("refs/heads/dependabot/cargo/test", "refs/remotes/origin/dependabot/github_actions/test"):
            for committer in (identities.DEPENDABOT, identities.GITHUB):
                self.assertTrue(identities.identity_allowed(ref, identities.DEPENDABOT, committer))
        for ref in ("refs/heads/main", "refs/heads/feature/dependabot/test", "refs/remotes/other/dependabot/test", "refs/tags/test"):
            self.assertFalse(identities.identity_allowed(ref, identities.DEPENDABOT, identities.GITHUB))

    def test_reviewed_dependabot_commit_is_allowed_after_merge(self):
        reviewed_sha = "b0b591ac08d5e2f342ab60499418e2c774b6947b"
        reviewed = {reviewed_sha}
        for ref in ("refs/heads/main", "refs/remotes/origin/main", "refs/tags/v0.1-test"):
            self.assertTrue(identities.identity_allowed(
                ref, identities.DEPENDABOT, identities.GITHUB,
                reviewed_sha, reviewed))
            self.assertFalse(identities.identity_allowed(
                ref, identities.DEPENDABOT, identities.GITHUB,
                "0" * 40, reviewed))
            self.assertFalse(identities.identity_allowed(
                ref, ("dependabot[bot]", "other@example.test"), identities.GITHUB,
                reviewed_sha, reviewed))

    def test_reviewed_automation_manifest_is_strict(self):
        reviewed = identities.load_reviewed_automation_commits()
        self.assertIn("b0b591ac08d5e2f342ab60499418e2c774b6947b", reviewed)

    def test_bot_name_does_not_trust_other_email_or_human_committer(self):
        ref = "refs/heads/dependabot/cargo/test"
        for author, committer in (
            (("dependabot[bot]", "other@example.test"), identities.GITHUB),
            (identities.DEPENDABOT, ("GitHub", "other@example.test")),
            (identities.DEPENDABOT, identities.HUMAN),
            (("random[bot]", "random@users.noreply.github.com"), identities.GITHUB),
        ):
            self.assertFalse(identities.identity_allowed(ref, author, committer))

    def test_external_human_contributor_history_is_allowed(self):
        with tempfile.TemporaryDirectory(prefix="macsploit-identities-") as directory:
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
            def git(*args, **extra):
                return subprocess.run(["git", *args], cwd=directory, env=dict(env, **extra), capture_output=True, check=True)
            git("init", "-b", "main")
            git("config", "user.name", identities.HUMAN[0])
            git("config", "user.email", identities.HUMAN[1])
            git("commit", "--allow-empty", "-m", "Synthetic root")
            git("commit", "--allow-empty", "-m", "External contribution",
                GIT_AUTHOR_NAME="Other Human", GIT_AUTHOR_EMAIL="other@example.test",
                GIT_COMMITTER_NAME="Other Human", GIT_COMMITTER_EMAIL="other@example.test")
            git("commit", "--allow-empty", "-m", "External web contribution",
                GIT_AUTHOR_NAME="Web Contributor", GIT_AUTHOR_EMAIL="web@example.test",
                GIT_COMMITTER_NAME=identities.GITHUB[0], GIT_COMMITTER_EMAIL=identities.GITHUB[1])
            result = subprocess.run(
                [os.sys.executable, str(ROOT / "scripts/check_identities.py")],
                cwd=directory, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_external_human_cannot_mask_owner_identity_mismatch(self):
        ref = "refs/heads/main"
        external = ("Other Human", "other@example.test")
        self.assertFalse(identities.identity_allowed(ref, external, identities.HUMAN))
        self.assertFalse(identities.identity_allowed(ref, identities.HUMAN, external))
        self.assertFalse(identities.identity_allowed(ref, external, identities.OWNER_GITHUB))
