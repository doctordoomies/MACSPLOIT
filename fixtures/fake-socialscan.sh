#!/bin/sh
# Offline fake of socialscan for MACSPLOIT tests. NO network activity.
#   --version                              -> version banner
#   <username|email> --json <file> --show-urls --view-by platform
#       writes <file> (platform-keyed lists of availability records), like upstream
#       2.0.1: every field is passed through str() (booleans become "True"/"False")
#       and None fields are omitted.
# Subjects select behavior deterministically:
#   octo-synthetic        -> GitHub taken (shared), Instagram available, Twitter error
#   researcher@example.test -> Pinterest registered, Firefox not registered,
#                            GitHub failed lookup (email platforms only)
#   malformed-synthetic   -> invalid JSON report
#   noreport-synthetic    -> exits 0 without writing a report
#   failing-synthetic     -> exits 2 with an error on stderr, no report
#   slow-synthetic        -> sleeps (cancellation / timeout tests), no report
#   anything else         -> empty object (zero results)
# Refuses (exit 64) if a prohibited mode is requested.
set -eu

for arg in "$@"; do
    case "$arg" in
        --version) echo "socialscan 2.0.1"; exit 0 ;;
        --available-only|--proxy-list|--proxy-list=*|--input|-i|--cache-tokens|-c)
            echo "fake-socialscan: prohibited $arg" >&2; exit 64 ;;
    esac
done

username="${1:-}"
case "$username" in -*|"") echo "fake-socialscan: expected username or email first" >&2; exit 2 ;; esac

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
  "GitHub": [{"platform": "GitHub", "query": "octo-synthetic", "available": "False", "valid": "True", "success": "True", "message": "Username is taken", "link": "https://github.com/octo-synthetic"}],
  "Instagram": [{"platform": "Instagram", "query": "octo-synthetic", "available": "True", "valid": "True", "success": "True", "message": "Username is available", "link": "https://www.instagram.com/octo-synthetic"}],
  "Twitter": [{"platform": "Twitter", "query": "octo-synthetic", "valid": "True", "success": "False", "message": "Rate limited"}]
}
JSON
        ;;
    researcher@example.test)
        cat > "$out" <<'JSON'
{
    "Pinterest": [{"platform": "Pinterest", "query": "researcher@example.test", "available": "False", "valid": "True", "success": "True", "message": "Email is already registered"}],
    "Firefox": [{"platform": "Firefox", "query": "researcher@example.test", "available": "True", "valid": "True", "success": "True", "message": "Available"}],
    "GitHub": [{"platform": "GitHub", "query": "researcher@example.test", "valid": "True", "success": "False", "message": "Unexpected response"}]
}
JSON
        ;;
    *) printf '{}' > "$out" ;;
esac
echo "Results written to $out"
