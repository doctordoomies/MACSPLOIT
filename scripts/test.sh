#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export MACOSX_DEPLOYMENT_TARGET=13.0
"${MACSPLOIT_CARGO:-cargo}" test --locked --workspace
./scripts/test-swift.sh
python3 -m unittest discover -s tests -v
python3 scripts/check_repository.py --reachable-history HEAD
python3 scripts/check_identities.py
