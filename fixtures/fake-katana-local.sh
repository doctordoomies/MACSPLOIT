#!/bin/sh
# Offline fake of Katana for MACSPLOIT local-target tests. NO network activity.
# Derives the crawl base from the `-u <url>` argument and emits deterministic JSONL:
#   * two same-host paths on the base (kept)
#   * a distinct loopback host and an off-host URL (both dropped by same-host filtering)
# Only loopback/synthetic hosts are used.
set -eu

for arg in "$@"; do
    if [ "$arg" = "-version" ]; then
        echo "katana version 1.3.0"
        exit 0
    fi
done

u=""
prev=""
for arg in "$@"; do
    [ "$prev" = "-u" ] && u="$arg"
    prev="$arg"
done
base=${u:-http://localhost:3000/}
case "$base" in
    */) : ;;
    *) base="$base/" ;;
esac

printf '%s\n' \
"{\"request\":{\"method\":\"GET\",\"endpoint\":\"${base}login\"},\"response\":{\"status_code\":200}}" \
"{\"request\":{\"method\":\"GET\",\"endpoint\":\"${base}dashboard\"},\"response\":{\"status_code\":200}}" \
'{"request":{"method":"GET","endpoint":"http://127.0.0.1:9999/other"}}' \
'{"request":{"method":"GET","endpoint":"http://evil.test/"}}' \
"{\"request\":{\"method\":\"GET\",\"endpoint\":\"${base}login\"}}"
