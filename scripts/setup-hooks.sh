#!/bin/sh
set -eu

cd "$(git rev-parse --show-toplevel)"
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required.' >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || {
    echo 'Python 3.10 or newer is required.' >&2
    exit 1
}
existing=$(git config --get core.hooksPath || true)
if [ -n "$existing" ] && [ "$existing" != '.githooks' ]; then
    echo 'A different hooks directory is configured; review it before changing it.' >&2
    exit 1
fi
if [ -z "$existing" ]; then
    hooks_dir=$(git rev-parse --git-path hooks)
    for hook in "$hooks_dir"/*; do
        case "$hook" in *.sample) continue ;; esac
        if [ -f "$hook" ] && [ -x "$hook" ]; then
            echo 'Existing executable Git hooks require review before replacement.' >&2
            exit 1
        fi
    done
fi
chmod +x .githooks/pre-commit .githooks/pre-push
git config --local core.hooksPath .githooks
echo 'MACSPLOIT commit and private-repository push checks enabled in this clone.'
