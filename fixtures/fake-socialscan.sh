#!/bin/sh
# Offline fake of socialscan for MACSPLOIT tests. NO network activity.
#   --version                              -> version banner
#   <username> --json <file> --show-urls --view-by platform
#       writes <file> (platform-keyed lists of availability records), like upstream.
# Subjects select behavior deterministically:
#   octo-synthetic        -> GitHub taken (shared), Instagram available, Twitter error
#   malformed-synthetic   -> invalid JSON report
#   noreport-synthetic    -> exits 0 without writing a report
#   failing-synthetic     -> exits 2 with an error on stderr, no report
#   slow-synthetic        -> sleeps (cancellation / timeout tests), no report
#   anything else         -> empty object (zero results)
# Refuses (exit 64) if a prohibited mode is requested.
set -eu

for arg in "$@"; do
    case "$arg" in
        --version) echo "socialscan 1.4.2"; exit 0 ;;
        --available-only|--proxy-list|--proxy-list=*|--input|-i|--cache-tokens|-c)
            echo "fake-socialscan: prohibited $arg" >&2; exit 64 ;;
    esac
done

username="${1:-}"
case "$username" in -*|"") echo "fake-socialscan: expected username first" >&2; exit 2 ;; esac

out=""; prev=""
for arg in "$@"; do
    [ "$prev" = "--json" ] && out="$arg"
    prev="$arg"
done
[ -n "$out" ] || { echo "fake-socialscan: no --json file" >&2; exit 2; }

case "$username" in
    slow-synthetic) sleep 30 ;;
    noreport-synthetic) : ;;
    failing-synthetic) echo "synthetic failure" >&2; exit 2 ;;
    malformed-synthetic) printf 'not json at all' > "$out" ;;
    octo-synthetic)
        cat > "$out" <<'JSON'
{
  "GitHub": [{"query": "octo-synthetic", "platform": "GitHub", "available": false, "valid": true, "success": true, "message": "Username is taken", "link": "https://github.com/octo-synthetic"}],
  "Instagram": [{"query": "octo-synthetic", "platform": "Instagram", "available": true, "valid": true, "success": true, "message": "Username is available"}],
  "Twitter": [{"query": "octo-synthetic", "platform": "Twitter", "available": null, "valid": true, "success": false, "message": "Rate limited"}]
}
JSON
        ;;
    *) printf '{}' > "$out" ;;
esac
echo "Results written to $out"
