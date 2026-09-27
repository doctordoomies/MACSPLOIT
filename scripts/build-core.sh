#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export MACOSX_DEPLOYMENT_TARGET=13.0
exec "${MACSPLOIT_CARGO:-cargo}" build --locked --package macsploit-core
