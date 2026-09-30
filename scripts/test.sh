#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export MACOSX_DEPLOYMENT_TARGET=13.0
"${MACSPLOIT_CARGO:-cargo}" test --locked --workspace
./scripts/build-core.sh
export MACSPLOIT_CORE_BINARY="$PWD/target/debug/macsploit-core"
# Offline fakes so the Swift Domain Recon bridge test never touches the network.
# Real subfinder and real DNS are never invoked by the automated suite.
export MACSPLOIT_SUBFINDER="$PWD/fixtures/fake-subfinder.sh"
export MACSPLOIT_DNS_FAKE="api.example.test=192.0.2.10;dev.example.test=192.0.2.11;auth.example.test=192.0.2.12"
./scripts/swift-command.sh test --disable-xctest --enable-swift-testing
python3 -m unittest discover -s tests -v
python3 scripts/check_repository.py --all-history
