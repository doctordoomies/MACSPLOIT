#!/bin/sh
# Offline fake of ProjectDiscovery's `subfinder`, used only by MACSPLOIT tests.
# It performs NO network activity. It mimics the two invocations MACSPLOIT makes:
#   * `-version`  -> prints a recognizable version string
#   * `-d DOMAIN -silent -oJ` -> prints deterministic JSONL subdomains for DOMAIN
# The output intentionally includes a case/format duplicate to exercise the
# parser's normalization and de-duplication.
set -eu

for arg in "$@"; do
    case "$arg" in
        -version)
            echo "fixture-subfinder version v9.9.9"
            exit 0
            ;;
    esac
done

domain=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -d)
            domain="${2:-}"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [ -z "$domain" ]; then
    echo "fake-subfinder: missing -d DOMAIN" 1>&2
    exit 2
fi

upper=$(printf '%s' "$domain" | tr '[:lower:]' '[:upper:]')
cat <<EOF
{"host":"api.$domain","source":"fixture"}
{"host":"API.$upper"}
{"host":"dev.$domain","source":"fixture"}
{"host":"auth.$domain"}
EOF
