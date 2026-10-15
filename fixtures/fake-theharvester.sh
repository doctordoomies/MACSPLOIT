#!/bin/sh
# Offline fake of theHarvester 4.11.1 for MACSPLOIT tests. NO network activity.
#   -h                                   -> banner with version, then usage
#   -d <domain> -b <sources> -l <n> -q -f <name>
#       writes <name>.json (upstream report schema) in the working directory.
# Domains (reserved .test names) select behavior:
#   example.test      -> hosts (incl. host:ip pairs), ips, emails, people, urls
#   empty.test        -> zero results
#   failing.test      -> exits 1 with an error, no report
#   malformed.test    -> writes an invalid JSON report
#   slow.test         -> sleeps (cancellation / timeout)
# Refuses (exit 64) every active/unsafe option MACSPLOIT must never pass:
# DNS resolution/lookup/brute force, takeover, Shodan, screenshots, API scans,
# proxies, virtual-host probing, custom DNS servers, and breach/"all" sources.
set -eu

banner() {
    echo '*******************************************************************'
    echo '* theHarvester 4.11.1                                             *'
    echo '*******************************************************************'
}

if [ "${1:-}" = "-h" ]; then banner; echo "usage: theHarvester [-h] -d DOMAIN [-l LIMIT] ..."; exit 0; fi

domain=""; sources=""; name=""; quiet=0
while [ $# -gt 0 ]; do
    case "$1" in
        -d) domain=$2; shift 2 ;;
        -b) sources=$2; shift 2 ;;
        -l) shift 2 ;;
        -f) name=$2; shift 2 ;;
        -q) quiet=1; shift ;;
        -r|--dns-resolve|-n|--dns-lookup|-c|--dns-brute|-t|--take-over|-s|--shodan|--screenshot|-a|--api-scan|-p|--proxies|-e|--dns-server|--vhost*|--routeviews|--dns-recursive-depth)
            echo "fake-theharvester: prohibited active option $1" >&2; exit 64 ;;
        *) echo "fake-theharvester: unexpected $1" >&2; exit 64 ;;
    esac
done
[ -n "$domain" ] && [ -n "$sources" ] && [ -n "$name" ] && [ "$quiet" = 1 ] || { echo "fake-theharvester: missing -d/-b/-f/-q" >&2; exit 64; }
case ",$sources," in
    *,all,*|*,dehashed,*|*,haveibeenpwned,*|*,hudsonrock,*|*,leaklookup,*|*,shodan,*)
        echo "fake-theharvester: prohibited source in $sources" >&2; exit 64 ;;
esac
case "$name" in */*) echo "fake-theharvester: report must be relative" >&2; exit 64 ;; esac

banner
echo "[*] Target: $domain"
case "$domain" in
    example.test)
        echo "[*] Searching Crtsh."
        printf '%s' '{"cmd":"-d example.test","emails":["person@example.test","someone@unrelated.test"],"hosts":["api.example.test","www.example.test:192.0.2.10","cdn.unrelated.test:198.51.100.7"],"ips":["192.0.2.20"],"asns":["AS64500"],"interesting_urls":["https://www.example.test/login"],"people":["Synthetic Person"],"shodan":[]}' > "$name.json"
        ;;
    empty.test) printf '%s' '{"cmd":"-d empty.test","hosts":[],"shodan":[]}' > "$name.json" ;;
    failing.test) echo "[!] An exception has occurred: synthetic failure"; exit 1 ;;
    malformed.test) printf '%s' '{"hosts": [' > "$name.json" ;;
    slow.test) sleep 30 ;;
    *) printf '%s' '{"hosts":[],"shodan":[]}' > "$name.json" ;;
esac
echo "[*] JSON File saved."
