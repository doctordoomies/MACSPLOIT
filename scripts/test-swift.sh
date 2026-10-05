#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export MACOSX_DEPLOYMENT_TARGET=13.0
./scripts/build-core.sh
export MACSPLOIT_CORE_BINARY="$PWD/target/debug/macsploit-core"
# Offline fakes so the Swift Domain Recon bridge test never touches the network.
# Real subfinder and real DNS are never invoked by the automated suite.
export MACSPLOIT_SUBFINDER="$PWD/fixtures/fake-subfinder.sh"
export MACSPLOIT_DNS_FAKE="api.example.test=192.0.2.10;dev.example.test=192.0.2.11;auth.example.test=192.0.2.12"
export MACSPLOIT_NMAP="$PWD/fixtures/fake-nmap.sh"
export MACSPLOIT_HTTPX="$PWD/fixtures/fake-httpx.sh"
export MACSPLOIT_WEB_FIXTURE="$PWD/fixtures/web-analysis-fixture.json"
export MACSPLOIT_KATANA="$PWD/fixtures/fake-katana.sh"
export MACSPLOIT_FFUF="$PWD/fixtures/fake-ffuf.sh"
export MACSPLOIT_FFUF_WORDLIST="$PWD/fixtures/content-discovery-small.txt"
# Force the empty, offline managed-download transport so no install path in any
# bridge test can reach the network (real release assets are never downloaded).
export MACSPLOIT_DOWNLOAD_FAKE=1
./scripts/swift-command.sh test --disable-xctest --enable-swift-testing
