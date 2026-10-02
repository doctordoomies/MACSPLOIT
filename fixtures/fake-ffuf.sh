#!/bin/sh
# Offline fake of ffuf for MACSPLOIT tests. NO network activity. Mimics:
#   * -V            -> prints a recognizable version string
#   * -u URL/FUZZ -w LIST ... -json -> prints deterministic ffuf JSON results
# Only synthetic documentation hosts are used by the tests that call this.
set -eu

for arg in "$@"; do
    case "$arg" in
        -V) echo "ffuf version v2.1.0"; exit 0 ;;
    esac
done

u=""; prev=""
for arg in "$@"; do
    [ "$prev" = "-u" ] && u="$arg"
    prev="$arg"
done
base=${u%FUZZ}
[ -z "$base" ] && base="https://example.test/"

cat <<EOF
{"results":[
{"url":"${base}admin","status":200,"length":120,"redirectlocation":""},
{"url":"${base}login","status":401,"length":40,"redirectlocation":""},
{"url":"${base}api","status":301,"length":0,"redirectlocation":"${base}api/"},
{"url":"${base}secret","status":403,"length":20,"redirectlocation":""},
{"url":"${base}missing","status":404,"length":0,"redirectlocation":""}
]}
EOF
