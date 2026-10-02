#!/usr/bin/env python3
"""Fail if a required job failed/cancelled/skipped or routing was incomplete."""
import json
import os
import sys


def verify(needs, kind):
    changes = needs['changes']
    if changes['result'] != 'success':
        raise ValueError('Change detection must succeed')
    output = changes['outputs']
    names = ('full', 'rust', 'swift', 'python', 'actions', 'policy', 'docs')
    if any(output.get(k) not in ('true', 'false') for k in names) or output['policy'] != 'true':
        raise ValueError('Incomplete or invalid routing outputs')
    flag = lambda k: output[k] == 'true'
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
