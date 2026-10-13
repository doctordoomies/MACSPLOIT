#!/bin/sh
# Offline fake of Maigret for MACSPLOIT tests. NO network activity.
#   --version                              -> version banner
#   <username> --json simple -fo <dir> --no-recursion --no-extracting ...
#       writes <dir>/report_<username>_simple.json, like upstream, only when the
#       "scan" finishes. The simple report lists ONLY claimed sites.
# Subjects select behavior deterministically:
#   octo-synthetic        -> GitHub (shared) + Keybase (unique to maigret)
#   malformed-synthetic   -> invalid JSON report
#   noreport-synthetic    -> exits 0 without writing a report
#   failing-synthetic     -> exits 2 with an error on stderr, no report
#   slow-synthetic        -> sleeps (cancellation / timeout tests), no report
#   anything else         -> empty object (zero results)
# Refuses (exit 64) if a prohibited mode is requested.
set -eu

for arg in "$@"; do
    case "$arg" in
        --version) echo "Maigret 0.5.0"; exit 0 ;;
        -a|--all-sites|--permute|--parse|--parse=*|--proxy|--proxy=*|--tor-proxy|--cloudflare-bypass|--ai)
            echo "fake-maigret: prohibited $arg" >&2; exit 64 ;;
    esac
done

username="${1:-}"
case "$username" in -*|"") echo "fake-maigret: expected username first" >&2; exit 2 ;; esac

folder=""; prev=""
for arg in "$@"; do
    [ "$prev" = "-fo" ] && folder="$arg"
    prev="$arg"
done
[ -n "$folder" ] || { echo "fake-maigret: no -fo folder" >&2; exit 2; }

out="$folder/report_${username}_simple.json"

case "$username" in
    slow-synthetic) sleep 30 ;;
    noreport-synthetic) : ;;
    failing-synthetic) echo "synthetic failure" >&2; exit 2 ;;
    malformed-synthetic) printf '{not valid json' > "$out" ;;
    octo-synthetic)
        cat > "$out" <<'JSON'
{
  "GitHub": {"url_main": "https://github.com", "url_user": "https://github.com/octo-synthetic", "status": {"status": "Claimed"}, "ids_data": {"name": "Octo Synthetic", "uid": "42"}},
  "Keybase": {"url_main": "https://keybase.io", "url_user": "https://keybase.io/octo-synthetic", "status": {"status": "Claimed"}}
}
JSON
        ;;
    *) printf '{}' > "$out" ;;
esac
echo "Finished. Report saved to $out"
