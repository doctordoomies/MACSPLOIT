"""Offline routing contracts, real Git events, and both required merge gates."""
import copy
import importlib.util
import itertools
import json
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


def route(*languages, full=False):
    return {'policy': True, 'rust': 'rust' in languages, 'swift': 'swift' in languages,
            'python': 'python' in languages, 'actions': 'actions' in languages,
            'full': full, 'docs': not languages}


ALL = route('rust', 'swift', 'python', 'actions', full=True)
CATEGORIES = [
    (route(), ['README.md', 'docs/roadmap.md', 'docs/adr/future.md', 'docs/notes.txt',
               'docs/guide.rst', 'CONTRIBUTING.md', 'LICENSE', 'assets/hero.png',
               'assets/Neon Rain Hacker Workspace.png', 'docs/café.md',
               'core/README.md', 'apps/macos/README.md', '.github/PULL_REQUEST_TEMPLATE.md',
               '.github/ISSUE_TEMPLATE/README.md']),
    (route('rust'), ['core/src/protocol.rs', 'core/tests/content_discovery.rs',
                     'core/tests/provider_status.rs', 'core/tests/future_provider.rs',
                     'core/migrations/future.sql', 'Cargo.toml', 'Cargo.lock', 'core/Cargo.toml',
                     '.cargo/config.toml', 'rust-toolchain', 'rust-toolchain.toml', 'scripts/build-core.sh']),
    (route('swift'), ['apps/macos/Sources/MACSPLOIT/Views/ToolManagerView.swift',
                      'apps/macos/Sources/MACSPLOITKit/Models/ProviderPresentation.swift',
                      'apps/macos/Tests/MACSPLOITKitTests/ProviderCenterTests.swift',
                      'apps/macos/Tests/MACSPLOITKitTests/FutureFeatureTests.swift',
                      'apps/macos/Package.swift', 'apps/macos/Package.resolved',
                      'apps/macos/Resources/Info.plist', 'scripts/swift-command.sh',
                      'scripts/build-macos.sh', 'scripts/run.sh']),
    (route('python'), ['scripts/check_repository.py', 'scripts/check_identities.py',
                       'tests/test_repository_policy.py', 'tests/test_identity_policy.py',
                       'scripts/reviewed-assets.json', 'scripts/reviewed-automation-commits.json',
                       'scripts/release-policy.json', '.gitignore']),
    (ALL, ['schemas/internal-protocol-v1.md', 'schemas/protocol-v2.md',
           'fixtures/fake-subfinder.sh', 'fixtures/fake-nmap.sh', 'fixtures/fake-httpx.sh',
           'fixtures/fake-katana.sh', 'fixtures/fake-ffuf.sh', 'fixtures/content-discovery-small.txt',
           'fixtures/future-provider.json', 'fixtures/README.md', 'providers/README.md',
           '.github/workflows/ci.yml', '.github/workflows/codeql.yml', '.github/workflows/future.yml',
           '.github/actions/future/action.yml', '.github/dependabot.yml', '.githooks/pre-push',
           'scripts/test.sh', 'scripts/test-swift.sh', 'scripts/classify_ci_changes.py',
           'scripts/check_ci_gate.py', 'tests/test_ci_routing.py', 'scripts/setup-hooks.sh',
           '.gitattributes', 'new-component/build.sh', 'tools/custom-file', 'new-language/source.xyz',
           'docs/example.py', 'docs/helper.rs', 'docs/test.swift', 'docs/run.sh', 'docs/example.svg',
           'newdir/test.rs', 'newdir/tool.swift', 'newdir/tool.py']),
    (route('rust', 'python'), ['core/helper.py']),
    (route('swift', 'python'), ['apps/macos/helper.py']),
    (route('rust', 'swift', full=True), ['core/bridge.swift', 'apps/macos/native.rs']),
]


class RoutingTests(unittest.TestCase):
    def test_exact_path_contract_for_pr_and_main(self):
        for expected, paths in CATEGORIES:
            for path, mode in itertools.product(paths, ('pr', 'push')):
                with self.subTest(path=path, mode=mode):
                    want = dict(expected)
                    if mode == 'push' and (want['rust'] or want['swift']):
                        want['full'] = True
                    self.assertEqual(router.classify([path], mode), want)

    def test_full_and_combination_invariants(self):
        self.assertEqual(router.everything(), ALL)
        self.assertEqual(set(router.KEYS), set(ALL))
        for left, right in itertools.product(CATEGORIES, repeat=2):
            paths = [left[1][0], right[1][0]]
            selected = router.classify(paths)
            self.assertIs(selected['policy'], True)
            self.assertEqual(selected, router.classify(reversed(paths)))
            for key in ('rust', 'swift', 'python', 'actions', 'full'):
                if left[0][key] or right[0][key]:
                    self.assertTrue(selected[key], (paths, key))
        self.assertEqual(router.classify(['core/src/protocol.rs', 'apps/macos/Sources/CoreClient.swift']),
                         route('rust', 'swift', full=True))
        for mode in ('full', '', None, 'typo'):
            self.assertEqual(router.classify(['README.md'], mode), ALL)

    def test_malformed_paths_never_earn_exemptions(self):
        for path in ['', '/README.md', '../README.md', 'docs/../README.md', 'docs/./a.md',
                     'docs//a.md', 'docs/a.md/', r'docs\a.md', 'docs/a\nREADME.md',
                     'docs/a\r.md', 'docs/a\t.md', 'docs/a\x00.md', 'docs/a\x7f.md',
                     'docs/a\x85.md', 'docs/a\u2028.md', 'docs/a\u2029.md', 'docs/a\u202e.md',
                     'docs/a\udcff.md', None, 1, {}, b'README.md']:
            with self.subTest(path=repr(path)):
                self.assertEqual(router.classify([path]), ALL)
        for paths in ([], None, 3, 'README.md', b'README.md'):
            self.assertEqual(router.classify(paths), ALL)
        self.assertEqual(router.classify(['README.md'], unsafe_paths=['README.md']), ALL)

    def test_event_fallbacks_do_not_need_git(self):
        for event, payload, ref in [('schedule', {}, 'refs/heads/main'),
                                    ('workflow_dispatch', {}, 'refs/heads/main'),
                                    ('unknown', {}, ''), ('push', {}, 'refs/heads/release/candidate'),
                                    ('push', {}, 'refs/heads/feature'), ('pull_request', {}, ''),
                                    ('push', [], 'refs/heads/main'), ('push', None, None),
                                    ('pull_request', {'pull_request': []}, 'refs/pull/1/merge')]:
            with patch.object(router, 'git') as git:
                self.assertEqual(router.from_event(event, payload, ref), ALL)
                git.assert_not_called()

    def test_cli_paths_and_malformed_event_files(self):
        for value, expected in [(b'README.md\n', route()), (b'core/src/lib.rs\n', route('rust')),
                                (b'apps/macos/Sources/App.swift\n', route('swift')),
                                (b'schemas/internal-protocol-v1.md\n', ALL), (b'unknown/path.sh\n', ALL),
                                (b'docs/a\xff.md\n', ALL), ('docs/a\u2028.md\n'.encode(), ALL)]:
            output = subprocess.check_output(['python3', str(ROOT / 'scripts/classify_ci_changes.py'), '--mode', 'pr'],
                                             input=value, env={'PATH': os.environ['PATH']})
            self.assertEqual(output.decode(), ''.join(f'{k}={str(v).lower()}\n' for k, v in expected.items()))
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / 'event.json'
            for contents in ('not json', 'null', '[]', '{"pull_request": null}'):
                event.write_text(contents)
                output = subprocess.check_output(['python3', str(ROOT / 'scripts/classify_ci_changes.py')],
                    env={'PATH': os.environ['PATH'], 'GITHUB_EVENT_PATH': str(event),
                         'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_REF': 'refs/pull/1/merge'})
                self.assertIn(b'full=true\n', output)


class GitEvents(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        self.git('init', '-b', 'main')
        self.git('config', 'user.name', 'Synthetic CI Test')
        self.git('config', 'user.email', 'ci@example.test')
        self.git('config', 'core.fileMode', 'true')
        self.write('README.md', 'base')
        self.base = self.commit()
        mock = patch.object(router, 'git', side_effect=self.git_bytes)
        mock.start()
        self.addCleanup(mock.stop)

    def git_bytes(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], env=self.env, stderr=subprocess.DEVNULL)

    def git(self, *args):
        return self.git_bytes(*args).decode().strip()

    def write(self, name, contents='synthetic fixture'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-m', 'Synthetic routing fixture')
        return self.git('rev-parse', 'HEAD')

    def event(self, base, head, mode='pr'):
        if mode == 'pr':
            return router.from_event('pull_request', {'pull_request': {'base': {'sha': base}, 'head': {'sha': head}}}, 'refs/pull/1/merge')
        return router.from_event('push', {'before': base, 'after': head, 'forced': False}, 'refs/heads/main')

    def test_edits_deletes_and_multi_commit_range(self):
        for name, expected in [('README.md', route()), ('core/src/lib.rs', route('rust')),
                               ('apps/macos/Sources/App.swift', route('swift')),
                               ('.github/workflows/future.yml', ALL), ('fixtures/fake-ffuf.sh', ALL),
                               ('schemas/protocol-v2.md', ALL), ('core/tests/future.rs', route('rust')),
                               ('apps/macos/Tests/Future.swift', route('swift')),
                               ('scripts/build-macos.sh', route('swift')), ('scripts/test.sh', ALL)]:
            with self.subTest(name=name):
                before = self.git('rev-parse', 'HEAD')
                path = self.write(name, 'changed')
                added = self.commit()
                self.assertEqual(self.event(before, added), expected)
                path.unlink()
                deleted = self.commit()
                self.assertEqual(self.event(added, deleted), expected)
        before = self.git('rev-parse', 'HEAD')
        self.write('core/src/new.rs')
        rust = self.commit()
        self.write('README.md', 'latest docs')
        docs = self.commit()
        self.assertEqual(self.event(rust, docs), route())
        self.assertEqual(self.event(before, docs, 'push'), route('rust', full=True))
        self.write('apps/macos/Sources/App.swift')
        mixed = self.commit()
        self.assertEqual(self.event(docs, mixed, 'push'), route('swift', full=True))
        self.assertEqual(self.event(before, mixed), route('rust', 'swift', full=True))

    def test_rename_retains_source_side_and_deletion(self):
        for source in ('core/src/file.rs', 'apps/macos/Sources/file.swift'):
            self.write(source)
            base = self.commit()
            destination = 'docs/' + Path(source).name + '.md'
            (self.root / 'docs').mkdir(exist_ok=True)
            self.git('mv', source, destination)
            renamed = self.commit()
            expected = route('rust' if source.endswith('.rs') else 'swift')
            self.assertEqual(self.event(base, renamed), expected)
            self.assertEqual(self.event(base, renamed, 'push'), dict(expected, full=True))

    def test_all_documentation_exemptions_reject_modes_in_both_trees(self):
        for name in ('README.md', 'docs/guide.md', 'assets/hero.png',
                     '.github/PULL_REQUEST_TEMPLATE.md', '.github/ISSUE_TEMPLATE/README.md'):
            for kind in ('executable', 'symlink'):
                with self.subTest(name=name, kind=kind):
                    path = self.write(name, kind)
                    base = self.commit()
                    if kind == 'executable':
                        path.chmod(0o755)
                    else:
                        path.unlink()
                        path.symlink_to('unresolved-synthetic-target')
                    changed = self.commit()
                    self.assertEqual(self.event(base, changed), ALL)
                    path.unlink()
                    deleted = self.commit()
                    self.assertEqual(self.event(changed, deleted), ALL)
        self.git('update-index', '--add', '--cacheinfo', f'160000,{self.base},assets/module.png')
        self.git('commit', '-m', 'Synthetic gitlink')
        self.assertEqual(self.event(self.base, self.git('rev-parse', 'HEAD')), ALL)

    def test_git_keeps_unusual_names_and_rejects_invalid_utf8(self):
        for name, expected in [('docs/space name.md', route()), ('docs/line\nbreak.md', ALL),
                               ('docs/line\tbreak.md', ALL), ('docs/control\x7f.md', ALL),
                               (r'docs/back\slash.md', ALL)]:
            before = self.git('rev-parse', 'HEAD')
            self.write(name)
            self.assertEqual(self.event(before, self.commit()), expected)
        # Write an index entry directly: APFS may refuse invalid UTF-8 filenames,
        # but a repository fetched from Linux can still contain those Git paths.
        before = self.git('rev-parse', 'HEAD')
        blob = subprocess.check_output(['git', '-C', str(self.root), 'hash-object', '-w', '--stdin'],
                                       input=b'synthetic', env=self.env).strip()
        subprocess.run(['git', '-C', str(self.root), 'update-index', '-z', '--index-info'],
                       input=b'100644 ' + blob + b'\tdocs/invalid-\xff.md\0', env=self.env, check=True)
        self.git('commit', '-m', 'Synthetic non-UTF-8 Git path')
        self.assertEqual(self.event(before, self.git('rev-parse', 'HEAD')), ALL)

    def test_uncertain_events_always_run_full(self):
        self.write('README.md', 'head')
        head = self.commit()
        push = {'before': self.base, 'after': head, 'forced': False}
        for field in ('before', 'after'):
            for bad in (None, '', 'bad', '0' * 40, 'f' * 40, 'a' * 41, 'a' * 63, '--help', 12):
                self.assertEqual(router.from_event('push', dict(push, **{field: bad}), 'refs/heads/main'), ALL)
            missing = dict(push)
            del missing[field]
            self.assertEqual(router.from_event('push', missing, 'refs/heads/main'), ALL)
        for forced in (True, None, 0, '', [], 'false'):
            self.assertEqual(router.from_event('push', dict(push, forced=forced), 'refs/heads/main'), ALL)
        self.assertEqual(router.from_event('push', {'before': self.base, 'after': head}, 'refs/heads/main'), ALL)
        self.assertEqual(self.event(head, self.base, 'push'), ALL)
        self.assertEqual(self.event(head, head), ALL)
        self.git('checkout', '-b', 'divergent', self.base)
        self.write('docs/other.md')
        other = self.commit()
        self.assertEqual(self.event(head, other, 'push'), ALL)
        for event in ('schedule', 'workflow_dispatch', 'unexpected'):
            self.assertEqual(router.from_event(event, push, 'refs/heads/main'), ALL)
        self.assertEqual(router.from_event('push', push, 'refs/heads/release/future'), ALL)
        with patch.object(router, 'git', side_effect=OSError('synthetic unavailable git')):
            self.assertEqual(self.event(self.base, head), ALL)


class GateTests(unittest.TestCase):
    def needs(self, result, kind):
        needs = {'changes': {'result': 'success', 'outputs': {k: str(v).lower() for k, v in result.items()}}}
        expected = ({'policy': True, 'rust': result['rust'], 'swift': result['swift'] and not result['full'], 'full': result['full']}
                    if kind == 'ci' else {k: result[k] for k in ('rust', 'swift', 'python', 'actions')})
        needs.update({k: {'result': 'success' if v else 'skipped'} for k, v in expected.items()})
        return needs

    def test_all_produced_routes_pass_both_gates(self):
        for category, mode, kind in itertools.product(CATEGORIES, ('pr', 'push', 'full'), ('ci', 'codeql')):
            gate.verify(self.needs(router.classify([category[1][0]], mode), kind), kind)

    def test_each_job_accepts_only_its_expected_result(self):
        for selected, kind in itertools.product((route(), route('swift'), ALL), ('ci', 'codeql')):
            original = self.needs(selected, kind)
            for job in original:
                expected = original[job]['result']
                for actual in ('success', 'skipped', 'failure', 'cancelled', 'pending', '', None, 1, [], {}):
                    if actual == expected:
                        continue
                    with self.subTest(kind=kind, job=job, actual=actual):
                        needs = copy.deepcopy(original)
                        needs[job]['result'] = actual
                        with self.assertRaisesRegex(ValueError, job):
                            gate.verify(needs, kind)

    def test_malformed_shapes_and_missing_or_extra_jobs(self):
        for kind in ('ci', 'codeql'):
            original = self.needs(ALL, kind)
            for shape in (None, [], 1, 'invalid', {}):
                with self.assertRaises(ValueError):
                    gate.verify(shape, kind)
            extra = dict(original, surprise={'result': 'failure'})
            with self.assertRaises(ValueError):
                gate.verify(extra, kind)
            for job in original:
                for shape in (None, [], 1, 'success', {}):
                    with self.assertRaises(ValueError):
                        gate.verify(dict(original, **{job: shape}), kind)
                missing = dict(original)
                del missing[job]
                with self.assertRaises(ValueError):
                    gate.verify(missing, kind)
            for shape in (None, [], 1, 'invalid', {}):
                needs = copy.deepcopy(original)
                needs['changes']['outputs'] = shape
                with self.assertRaises(ValueError):
                    gate.verify(needs, kind)
            for key in ALL:
                for invalid in ('True', 'False', '1', 'yes', None, True, 1, [], {}):
                    needs = copy.deepcopy(original)
                    needs['changes']['outputs'][key] = invalid
                    with self.assertRaisesRegex(ValueError, key):
                        gate.verify(needs, kind)
                needs = copy.deepcopy(original)
                del needs['changes']['outputs'][key]
                with self.assertRaises(ValueError):
                    gate.verify(needs, kind)
            needs = copy.deepcopy(original)
            needs['changes']['outputs']['surprise'] = 'true'
            with self.assertRaises(ValueError):
                gate.verify(needs, kind)

    def test_contradictory_routes_and_policy_false_are_refused(self):
        for invalid in (dict(route(), policy=False), dict(route(), docs=False), dict(route(), full=True),
                        dict(ALL, docs=True), dict(ALL, full=False)):
            for kind in ('ci', 'codeql'):
                with self.assertRaises(ValueError):
                    gate.verify(self.needs(invalid, kind), kind)
        with self.assertRaises(ValueError):
            gate.verify({}, 'unknown')

    def test_cli_refuses_malformed_needs_cleanly(self):
        for kind in ('ci', 'codeql'):
            for value, status in [(self.needs(ALL, kind), 0), ([], 1), (None, 1),
                                  ({'changes': {'result': 'success', 'outputs': []}}, 1)]:
                result = subprocess.run(['python3', str(ROOT / 'scripts/check_ci_gate.py'), kind],
                    env={'PATH': os.environ['PATH'], 'CI_NEEDS': json.dumps(value)}, capture_output=True, text=True)
                self.assertEqual(result.returncode, status)
                self.assertNotIn('Traceback', result.stderr)
