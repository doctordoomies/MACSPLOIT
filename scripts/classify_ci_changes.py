#!/usr/bin/env python3
"""Conservative CI routing. Unknown paths/diffs request all validation.

CI reads SHAs from the event JSON, never interpolates event text into a shell.
Git's NUL-delimited diff preserves unusual filenames and both sides of renames.
For local use: --mode pr|push|full with newline-separated paths on stdin.
"""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

KEYS = ('policy', 'rust', 'swift', 'python', 'actions', 'full', 'docs')
DOC_FILES = {'README.md', 'AGENTS.md', 'CHANGELOG.md', 'CONTRIBUTING.md',
             'CODE_OF_CONDUCT.md', 'SUPPORT.md', 'SECURITY.md', 'NOTICE', 'LICENSE',
             'core/README.md', 'apps/macos/README.md'}
POLICY_DATA = {'scripts/reviewed-assets.json', 'scripts/reviewed-automation-commits.json',
               'scripts/release-policy.json', '.gitignore'}


def everything():
    return dict.fromkeys(KEYS[:-1], True) | {'docs': False}


def classify(paths, mode='pr', unsafe_paths=()):
    paths = list(paths)
    if mode not in ('pr', 'push') or not paths or unsafe_paths:
        return everything()
    result = dict.fromkeys(KEYS, False)
    result['policy'] = True
    for path in paths:
        p = PurePosixPath(path)
        if p.is_absolute() or '..' in p.parts or '\\' in path or any(ord(c) < 32 for c in path):
            return everything()
        # Shared inputs precede any documentation exemption.
        if path.startswith(('schemas/', 'fixtures/', 'providers/', '.github/workflows/', '.github/actions/')) or path in {
            'scripts/classify_ci_changes.py', 'scripts/check_ci_gate.py',
            'tests/test_ci_routing.py', 'scripts/test.sh', 'scripts/test-swift.sh',
        }:
            return everything()
        if path in DOC_FILES or (path.startswith('docs/') and p.suffix in {'.md', '.rst', '.txt'}) or (
            path.startswith('assets/') and p.suffix.lower() in {'.png', '.jpg', '.jpeg', '.webp'}
        ) or path in {'.github/PULL_REQUEST_TEMPLATE.md', '.github/ISSUE_TEMPLATE/README.md'}:
            continue
        # A source file in a new location must not lose its language scan.
        for suffix, language in (('.rs', 'rust'), ('.swift', 'swift'), ('.py', 'python')):
            if p.suffix == suffix:
                result[language] = True
        if path.startswith(('core/', '.cargo/')) or path in {'Cargo.toml', 'Cargo.lock', 'rust-toolchain', 'rust-toolchain.toml', 'scripts/build-core.sh'}:
            result['rust'] = True
        elif path.startswith('apps/macos/') or path in {'scripts/build-macos.sh', 'scripts/swift-command.sh', 'scripts/run.sh'}:
            result['swift'] = True
        elif (path.startswith(('scripts/', 'tests/')) and p.suffix == '.py') or path in POLICY_DATA:
            result['python'] = True
        else:
            return everything()
    result['docs'] = not any(result[k] for k in ('rust', 'swift', 'python', 'actions'))
    # All application changes on main receive the complete macOS integration suite.
    result['full'] = (mode == 'push' and (result['rust'] or result['swift'])) or (
        result['rust'] and result['swift'])
    return result


def git(*args):
    return subprocess.check_output(['git', *args], stderr=subprocess.DEVNULL)


def from_event(event_name, event, ref):
    if not isinstance(event, dict) or not isinstance(ref, str):
        return everything()
    if event_name in ('workflow_dispatch', 'schedule') or ref.startswith('refs/heads/release/'):
        return everything()
    try:
        if event_name == 'pull_request':
            base, head = event['pull_request']['base']['sha'], event['pull_request']['head']['sha']
            mode = 'pr'
        elif event_name == 'push' and ref == 'refs/heads/main' and not event.get('forced'):
            base, head = event['before'], event['after']
            mode = 'push'
        else:
            return everything()
        for sha in (base, head):
            if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{40,64}', sha) or set(sha) == {'0'}:
                return everything()
            git('cat-file', '-e', sha + '^{commit}')
        if mode == 'push':
            git('merge-base', '--is-ancestor', base, head)
        raw = git('diff', '--name-only', '--no-renames', '-z', base, head, '--')
        paths = [p.decode('utf-8', errors='strict') for p in raw.split(b'\0') if p]
        # A chmod/symlink disguised as documentation is executable/security input.
        unsafe = []
        for sha in (base, head):
            for entry in git('ls-tree', '-r', '-z', sha).split(b'\0'):
                if not entry:
                    continue
                metadata, name = entry.split(b'\t', 1)
                path = name.decode('utf-8', errors='strict')
                if path in paths and metadata.split()[0] != b'100644':
                    if path in DOC_FILES or path.startswith(('docs/', 'assets/')):
                        unsafe.append(path)
        return classify(paths, mode, unsafe)
    except (KeyError, TypeError, ValueError, UnicodeError, subprocess.CalledProcessError, OSError):
        return everything()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('pr', 'push', 'full'))
    args = parser.parse_args()
    if args.mode:
        result = classify(sys.stdin.read().splitlines(), args.mode)
    else:
        try:
            event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
            result = from_event(os.environ.get('GITHUB_EVENT_NAME', ''), event, os.environ.get('GITHUB_REF', ''))
        except (KeyError, OSError, ValueError):
            result = everything()
    output = ''.join(f'{k}={str(v).lower()}\n' for k, v in result.items())
    print(output, end='')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write(output)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
            stream.write('### Change routing\n\n```text\n' + output + '```\n')


if __name__ == '__main__':
    main()
