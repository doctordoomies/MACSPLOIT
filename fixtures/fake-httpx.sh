#!/bin/sh
# Offline fake of ProjectDiscovery httpx, used only by MACSPLOIT tests. It performs
# NO network activity. It mimics:
#   * `-version`                 -> prints a recognizable version string
#   * `... -u url1,url2 -json ...`-> prints one JSON line per probed URL
# Every probed URL reports status 200, an nginx server, and a title. Only synthetic
# documentation addresses are ever used by the tests that call this.
set -eu

for arg in "$@"; do
    case "$arg" in
        -version|-v) echo "httpx version v1.6.0"; exit 0 ;;
    esac
done

# Find the value following -u (comma-separated URL list).
urls=""
prev=""
for arg in "$@"; do
    if [ "$prev" = "-u" ]; then urls="$arg"; fi
    prev="$arg"
done

[ -z "$urls" ] && exit 0

# Emit one JSON object per URL (comma-separated).
IFS=,
for url in $urls; do
    # Derive host from scheme://host:port
    hostport=${url#*://}
    host=${hostport%%:*}
    printf '{"url":"%s","input":"%s","status_code":200,"title":"MACSPLOIT Demo","webserver":"nginx","content_length":1024,"host":"%s","tech":["nginx"]}\n' \
        "$url" "$url" "$host"
done
