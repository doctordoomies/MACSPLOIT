#!/bin/sh
# Offline fake of user-scanner 1.5.2.1 for MACSPLOIT tests. NO network activity.
#   --version                         -> upstream version banner
#   --username=<h> | --email=<e> ... --format json --output <file>
#       writes a static fixture (selected by subject) to <file>, like upstream,
#       only when the "scan" finishes.
# Subjects select behavior deterministically:
#   octo-synthetic / researcher@example.test -> representative results
#   malformed-synthetic   -> invalid JSON report
#   noreport-synthetic    -> exits 0 without writing a report
#   failing-synthetic     -> exits 2 with an error on stderr, no report
#   slow-synthetic        -> sleeps (cancellation / timeout tests), no report
#   flood-synthetic       -> floods stdout (output bound), then a normal report
# The fake refuses (exit 64) if a prohibited mode is requested or if the private
# config that disables upstream's PyPI update check is missing.
set -eu
here=$(cd "$(dirname "$0")" && pwd)

for arg in "$@"; do
    case "$arg" in
        --version) echo "user-scanner current version -> 1.5.2.1"; exit 0 ;;
        --cross-scan|--hudson|--hudson-scan|--proxy-file*|-P|--validate-proxies|--allow-loud|--email-domains*|--update|-U|--all|-uf|-ef|--username-file*|--email-file*)
            echo "fake-user-scanner: prohibited option $arg" >&2; exit 64 ;;
    esac
done

if [ -z "${USER_SCANNER_CONFIG:-}" ] || ! grep -q '"auto_update_status": false' "$USER_SCANNER_CONFIG"; then
    echo "fake-user-scanner: private config missing" >&2; exit 64
fi

subject=""; output=""; prev=""
for arg in "$@"; do
    case "$arg" in
        --username=*) subject=${arg#--username=} ;;
        --email=*) subject=${arg#--email=} ;;
    esac
    [ "$prev" = "--output" ] && output="$arg"
    prev="$arg"
done
[ -n "$subject" ] && [ -n "$output" ] || { echo "usage" >&2; exit 2; }

echo "      user-scanner (fake) Version: 1.5.2.1"
echo " Checking target: $subject"

case "$subject" in
    octo-synthetic) cp "$here/user-scanner/username-octo-1.5.2.1.json" "$output" ;;
    researcher@example.test) cp "$here/user-scanner/email-registered-1.5.2.1.json" "$output" ;;
    malformed-synthetic) printf '[{"status": "Found", "site_name": ' > "$output" ;;
    noreport-synthetic) : ;;
    failing-synthetic) echo "Traceback: synthetic failure" >&2; exit 2 ;;
    slow-synthetic) sleep 30 ;;
    flood-synthetic)
        i=0
        while [ $i -lt 40000 ]; do echo "progress line $i ................................"; i=$((i+1)); done
        cp "$here/user-scanner/username-octo-1.5.2.1.json" "$output" ;;
    *) printf '[]' > "$output" ;;
esac
echo "[+] JSON Results saved to $output"
