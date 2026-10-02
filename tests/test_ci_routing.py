"""Routing and gate regressions, including real Git diff edge cases."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


router = load('classify_ci_changes')
gate = load('check_ci_gate')


class RoutingTests(unittest.TestCase):
    def test_docs_no_build_or_language_scan_for_pr_and_main(self):
        for path in ['README.md', 'docs/architecture.md', 'CONTRIBUTING.md', 'LICENSE', 'assets/hero.png']:
            for mode in ('pr', 'push'):
                result = router.classify([path], mode)
                self.assertTrue(result['policy'])
                self.assertTrue(result['docs'])
                self.assertFalse(any(result[k] for k in ('rust', 'swift', 'full', 'python', 'actions')))

    def test_rust_paths_and_dependencies(self):
        for path in ['core/src/providers/mod.rs', 'Cargo.lock', 'core/Cargo.toml', '.cargo/config.toml', 'scripts/build-core.sh']:
            result = router.classify([path])
            self.assertTrue(result['rust'])
            self.assertFalse(result['swift'])
            self.assertFalse(result['full'])
            self.assertTrue(router.classify([path], 'push')['full'])

    def test_swift_paths_and_build(self):
        for path in ['apps/macos/Sources/MACSPLOIT/App.swift', 'apps/macos/Package.swift', 'scripts/swift-command.sh', 'scripts/build-macos.sh']:
            result = router.classify([path])
            self.assertTrue(result['swift'])
            self.assertFalse(result['rust'])
            self.assertFalse(result['full'])
            self.assertTrue(router.classify([path], 'push')['full'])

    def test_shared_inputs_and_workflow_self_validation(self):
        for path in ['schemas/internal-protocol-v1.md', 'fixtures/fake-nmap.sh', 'fixtures/data.json', 'providers/adapter.toml',
                     '.github/workflows/ci.yml', '.github/workflows/codeql.yml', '.github/actions/test/action.yml',
                     'scripts/test.sh', 'scripts/test-swift.sh', 'scripts/classify_ci_changes.py', 'scripts/check_ci_gate.py', 'tests/test_ci_routing.py']:
            self.assertEqual(router.classify([path]), router.everything(), path)

    def test_policy_and_python(self):
        for path in ['scripts/check_repository.py', 'scripts/check_identities.py', 'scripts/reviewed-automation-commits.json',
                     'scripts/reviewed-assets.json', 'tests/test_repository_policy.py', 'tests/test_identity_policy.py']:
            result = router.classify([path])
            self.assertTrue(result['policy'] and result['python'])
            self.assertFalse(result['rust'] or result['swift'])

    def test_unknown_empty_and_malicious_paths_fail_full(self):
        for paths in [[], ['new/build.sh'], ['docs/run.py'], ['docs/example.svg'], ['README.md\ncore/a.rs'], ['../README.md'], ['/README.md']]:
            self.assertEqual(router.classify(paths), router.everything())
        self.assertEqual(router.classify(['README.md'], unsafe_paths=['README.md']), router.everything())

    def test_mixed_and_full_modes(self):
        self.assertTrue(router.classify(['core/a.rs', 'apps/macos/a.swift'])['full'])
        for event in ['schedule', 'workflow_dispatch', 'unknown']:
            self.assertEqual(router.from_event(event, {}, ''), router.everything())
        self.assertEqual(router.from_event('push', {}, 'refs/heads/release/public-launch'), router.everything())
        for event in (None, [], 'invalid'):
            self.assertEqual(router.from_event('push', event, 'refs/heads/main'), router.everything())

    def test_real_git_events_rename_delete_modes_and_missing_base(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=directory, stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-b', 'main')
            git('config', 'user.name', 'Synthetic CI Test')
            git('config', 'user.email', 'ci@example.test')
            root = Path(directory)
            (root / 'README.md').write_text('before')
            (root / 'core').mkdir()
            (root / 'core/a.rs').write_text('fn main() {}')
            git('add', '.'); git('commit', '-m', 'Synthetic base')
            base = git('rev-parse', 'HEAD')
            (root / 'README.md').write_text('after')
            git('add', '.'); git('commit', '-m', 'Synthetic docs')
            head = git('rev-parse', 'HEAD')
            def repo_git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], stderr=subprocess.DEVNULL)
            with patch.object(router, 'git', side_effect=repo_git):
                push = {'before': base, 'after': head}
                self.assertTrue(router.from_event('push', push, 'refs/heads/main')['docs'])
                pr = {'pull_request': {'base': {'sha': base}, 'head': {'sha': head}}}
                self.assertTrue(router.from_event('pull_request', pr, 'refs/pull/1/merge')['docs'])
                for bad in ['0' * 40, 'f' * 40, 'bad', None]:
                    self.assertEqual(router.from_event('push', dict(push, before=bad), 'refs/heads/main'), router.everything())
                self.assertEqual(router.from_event('push', dict(push, forced=True), 'refs/heads/main'), router.everything())
                self.assertEqual(router.from_event('push', {'before': head, 'after': base}, 'refs/heads/main'), router.everything())
                (root / 'docs').mkdir()
                git('mv', 'core/a.rs', 'docs/moved.md')
                git('commit', '-m', 'Synthetic rename')
                renamed = git('rev-parse', 'HEAD')
                result = router.from_event('push', {'before': head, 'after': renamed}, 'refs/heads/main')
                self.assertTrue(result['rust'] and result['full'])
                os.chmod(root / 'README.md', 0o755)
                git('add', '.'); git('commit', '-m', 'Synthetic executable docs')
                self.assertEqual(router.from_event('push', {'before': renamed, 'after': git('rev-parse', 'HEAD')}, 'refs/heads/main'), router.everything())
                git('rm', 'README.md'); git('commit', '-m', 'Synthetic delete executable docs')
                self.assertEqual(router.from_event('push', {'before': renamed, 'after': git('rev-parse', 'HEAD')}, 'refs/heads/main')['policy'], True)


class GateTests(unittest.TestCase):
    def needs(self, result, kind):
        output = {k: str(v).lower() for k, v in result.items()}
        needs = {'changes': {'result': 'success', 'outputs': output}}
        if kind == 'ci':
            expected = {'policy': True, 'rust': result['rust'], 'swift': result['swift'] and not result['full'], 'full': result['full']}
        else:
            expected = {k: result[k] for k in ('rust', 'swift', 'python', 'actions')}
        needs.update({k: {'result': 'success' if v else 'skipped'} for k, v in expected.items()})
        return needs

    def test_expected_routes_pass_both_gates(self):
        for paths in [['README.md'], ['core/a.rs'], ['apps/macos/a.swift'], ['schemas/x'], ['scripts/check_repository.py']]:
            for mode in ('pr', 'push', 'full'):
                for kind in ('ci', 'codeql'):
                    gate.verify(self.needs(router.classify(paths, mode), kind), kind)

    def test_required_skips_failures_cancellations_and_missing_outputs_rejected(self):
        for kind in ('ci', 'codeql'):
            for state in ('skipped', 'failure', 'cancelled'):
                needs = self.needs(router.everything(), kind)
                needs['rust']['result'] = state
                with self.assertRaises(ValueError): gate.verify(needs, kind)
            needs = self.needs(router.everything(), kind)
            needs['changes']['result'] = 'skipped'
            with self.assertRaises(ValueError): gate.verify(needs, kind)
            needs = self.needs(router.everything(), kind)
            del needs['changes']['outputs']['rust']
            with self.assertRaises(ValueError): gate.verify(needs, kind)

    def test_policy_cannot_be_skipped_on_docs(self):
        needs = self.needs(router.classify(['README.md']), 'ci')
        needs['policy']['result'] = 'skipped'
        with self.assertRaises(ValueError): gate.verify(needs, 'ci')
