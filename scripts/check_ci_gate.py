#!/usr/bin/env python3
"""Fail if a required job failed/cancelled/skipped or routing was incomplete."""
import json
import os
import sys


def verify(needs, kind):
    jobs = {'ci': {'policy', 'rust', 'swift', 'full'},
            'codeql': {'rust', 'swift', 'python', 'actions'}}
    if not isinstance(kind, str) or kind not in jobs:
        raise ValueError('Unknown gate')
    if not isinstance(needs, dict):
        raise ValueError(f'{kind}: expected needs object')
    expected_jobs = jobs[kind] | {'changes'}
    if set(needs) != expected_jobs:
        missing = ', '.join(sorted(expected_jobs - set(needs))) or 'none'
        raise ValueError(f'{kind}: missing jobs: {missing}; unexpected job count: {len(set(needs) - expected_jobs)}')
    for job, data in needs.items():
        if not isinstance(data, dict) or not isinstance(data.get('result'), str):
            raise ValueError(f'{job}: expected job object with a string result')
    changes = needs['changes']
    if changes['result'] != 'success':
        raise ValueError(f'changes: expected success, got {changes["result"]!r}')
    output = changes.get('outputs')
    names = {'full', 'rust', 'swift', 'python', 'actions', 'policy', 'docs'}
    if not isinstance(output, dict) or set(output) != names:
        raise ValueError('changes.outputs: expected exactly the seven routing keys')
    for name in sorted(names):
        if not isinstance(output[name], str) or output[name] not in ('true', 'false'):
            raise ValueError(f'changes.outputs.{name}: expected "true" or "false"')
    flag = lambda k: output[k] == 'true'
    if not flag('policy'):
        raise ValueError('changes.outputs.policy: expected true, got false')
    languages = any(flag(k) for k in ('rust', 'swift', 'python', 'actions'))
    if flag('docs') == languages:
        raise ValueError('changes.outputs.docs: must be true exactly when all languages are false')
    if flag('full') and not (flag('rust') or flag('swift')):
        raise ValueError('changes.outputs.full: requires Rust or Swift validation')
    if flag('rust') and flag('swift') and not flag('full'):
        raise ValueError('changes.outputs.full: expected true for mixed Rust and Swift')
    if kind == 'ci':
        expected = {'policy': True, 'rust': flag('rust'),
                    'swift': flag('swift') and not flag('full'), 'full': flag('full')}
    elif kind == 'codeql':
        expected = {k: flag(k) for k in ('rust', 'swift', 'python', 'actions')}
    else:
        raise ValueError('Unknown gate')
    for job, required in expected.items():
        want = 'success' if required else 'skipped'
        if needs[job]['result'] != want:
            raise ValueError(f'{job}: expected {want}, got {needs[job]["result"]}')


if __name__ == '__main__':
    try:
        verify(json.loads(os.environ['CI_NEEDS']), sys.argv[1])
    except (KeyError, ValueError, TypeError, IndexError) as error:
        print(f'Gate refused: {error}', file=sys.stderr)
        sys.exit(1)
    print('All required jobs succeeded; only intentionally irrelevant jobs skipped.')
