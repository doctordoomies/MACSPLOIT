#!/bin/sh
# Offline fake of PhoneInfoga v2.11.0 for MACSPLOIT tests. NO network activity.
#   version                          -> version banner
#   scan --number=<E.164> --disable=...
#       prints the upstream console renderer ("Results for <scanner>" sections,
#       optional error block, "<N> scanner(s) succeeded").
# Numbers (fictional 555-01xx / ARCEP test ranges) select behavior:
#   +33199001234  -> local + ovh results
#   +12025550143  -> local results + an ovh error
#   +12025550166  -> zero results
#   +12025550177  -> invalid number: exit 1 with the error on stderr
#   +12025550188  -> slow (cancellation / timeout)
#   +12025550199  -> malformed output (no trailer)
#   +12025550155  -> floods stdout past the capture bound
# Refuses (exit 64) plugins, env files, serve mode, or enabling disabled scanners.
set -eu

[ "${1:-}" = "version" ] && { echo "PhoneInfoga v2.11.0-55807b0"; exit 0; }
[ "${1:-}" = "scan" ] || { echo "fake-phoneinfoga: only version/scan" >&2; exit 64; }
shift
number=""; disabled=""
for arg in "$@"; do
    case "$arg" in
        --number=*) number=${arg#--number=} ;;
        --disable=*) disabled="$disabled ${arg#--disable=}" ;;
        --plugin*|--env-file*) echo "fake-phoneinfoga: prohibited $arg" >&2; exit 64 ;;
        *) echo "fake-phoneinfoga: unexpected $arg" >&2; exit 64 ;;
    esac
done
for s in numverify googlecse googlesearch; do
    case "$disabled" in *" $s"*) ;; *) echo "fake-phoneinfoga: $s must be disabled" >&2; exit 64 ;; esac
done

echo "Running scan for phone number $number..."
echo
case "$number" in
    +33199001234)
        printf 'Results for local\nRaw local: 0199001234\nLocal: 01 99 00 12 34\nE164: +33199001234\nInternational: 33199001234\nCountry code: 33\nCountry: FR\nCarrier: \n\nResults for ovh\nFound: true\nNumber range: 0199xxxxxx\nCity: Paris\nZip code: 75001\n\n2 scanner(s) succeeded\n' ;;
    +12025550143)
        printf 'Results for local\nRaw local: 2025550143\nLocal: (202) 555-0143\nE164: +12025550143\nInternational: 12025550143\nCountry code: 1\nCountry: US\nCarrier: \n\nThe following scanners returned errors:\novh: country lookup failed\n\n1 scanner(s) succeeded\n' ;;
    +12025550166) printf '0 scanner(s) succeeded\n' ;;
    +12025550177) echo "given phone number is not valid" >&2; exit 1 ;;
    +12025550188) sleep 30 ;;
    +12025550199) printf 'Results for local\nE164 +12025550199 without colon\n' ;;
    +12025550155)
        i=0; while [ $i -lt 12000 ]; do echo "Results for local"; echo "Country: noise $i ................"; i=$((i+1)); done ;;
    *) printf '0 scanner(s) succeeded\n' ;;
esac
