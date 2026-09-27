#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
./scripts/build-macos.sh
exec open "$PWD/build/MACSPLOIT.app"
