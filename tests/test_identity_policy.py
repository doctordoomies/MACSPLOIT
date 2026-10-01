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
    def test_human_author_and_committer_must_both_match(self):
        for ref in ("refs/heads/main", "refs/heads/release/public-launch",
                    "refs/heads/feature/test", "refs/remotes/origin/dependabot/cargo/test"):
            self.assertTrue(identities.identity_allowed(ref, identities.HUMAN, identities.HUMAN))
            self.assertFalse(identities.identity_allowed(ref, identities.HUMAN, identities.GITHUB))
            self.assertFalse(identities.identity_allowed(ref, ("Other Human", "other@example.test"), identities.HUMAN))

    def test_exact_dependabot_pairs_only_on_automation_branches(self):
        for ref in ("refs/heads/dependabot/cargo/test", "refs/remotes/origin/dependabot/github_actions/test"):
            for committer in (identities.DEPENDABOT, identities.GITHUB):
                self.assertTrue(identities.identity_allowed(ref, identities.DEPENDABOT, committer))
        for ref in ("refs/heads/main", "refs/heads/feature/dependabot/test", "refs/remotes/other/dependabot/test", "refs/tags/test"):
            self.assertFalse(identities.identity_allowed(ref, identities.DEPENDABOT, identities.GITHUB))

    def test_bot_name_does_not_trust_other_email_or_human_committer(self):
        ref = "refs/heads/dependabot/cargo/test"
        for author, committer in (
            (("dependabot[bot]", "other@example.test"), identities.GITHUB),
            (identities.DEPENDABOT, ("GitHub", "other@example.test")),
            (identities.DEPENDABOT, identities.HUMAN),
            (("random[bot]", "random@users.noreply.github.com"), identities.GITHUB),
            (("Other Human", "other@example.test"), identities.GITHUB),
        ):
            self.assertFalse(identities.identity_allowed(ref, author, committer))

    def test_reachable_non_tip_human_identity_is_rejected_without_echo(self):
        with tempfile.TemporaryDirectory(prefix="macsploit-identities-") as directory:
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
            def git(*args, **extra):
                return subprocess.run(["git", *args], cwd=directory, env=dict(env, **extra), capture_output=True, check=True)
            git("init", "-b", "main")
            git("config", "user.name", identities.HUMAN[0])
            git("config", "user.email", identities.HUMAN[1])
            git("commit", "--allow-empty", "-m", "Synthetic root")
            git("switch", "-c", "dependabot/cargo/test")
            git("commit", "--allow-empty", "-m", "Synthetic dependency update",
                GIT_AUTHOR_NAME=identities.DEPENDABOT[0], GIT_AUTHOR_EMAIL=identities.DEPENDABOT[1],
                GIT_COMMITTER_NAME=identities.GITHUB[0], GIT_COMMITTER_EMAIL=identities.GITHUB[1])
            def check():
                return subprocess.run([os.sys.executable, str(ROOT / "scripts/check_identities.py")],
                                      cwd=directory, env=env, capture_output=True, text=True)
            self.assertEqual(check().returncode, 0)
            git("commit", "--allow-empty", "-m", "Synthetic unapproved human",
                GIT_AUTHOR_NAME="Other Human", GIT_AUTHOR_EMAIL="other@example.test")
            git("commit", "--allow-empty", "-m", "Canonical tip cannot hide earlier identity")
            result = check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("BLOCKED identity", result.stderr)
            self.assertNotIn("other@example.test", result.stdout + result.stderr)
