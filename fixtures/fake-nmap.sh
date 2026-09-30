#!/bin/sh
# Offline fake of Nmap, used only by MACSPLOIT tests. It performs NO network
# activity. It mimics the two invocations MACSPLOIT makes:
#   * `--version`            -> prints a recognizable version string
#   * `... -oX - <ip> [<ip>]`-> prints deterministic Nmap XML for each IP target
# Every scanned host reports 22/tcp (ssh) and 443/tcp (https) open. Only synthetic
# documentation addresses are ever used by the tests that call this.
set -eu

for arg in "$@"; do
    case "$arg" in
        --version|-V)
            echo "Nmap version 7.95 ( https://nmap.org )"
            exit 0
            ;;
    esac
done

# Collect IP-like trailing arguments (skip options and their values).
targets=""
for arg in "$@"; do
    case "$arg" in
        -*) continue ;;              # options
        -) continue ;;
        *:*) targets="$targets $arg" ;;   # IPv6
        *.*.*.*) targets="$targets $arg" ;; # IPv4
        *) continue ;;
    esac
done

printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
printf '%s\n' '<nmaprun scanner="nmap" args="fake">'
for ip in $targets; do
    case "$ip" in
        *:*) addrtype="ipv6" ;;
        *)   addrtype="ipv4" ;;
    esac
    printf '  <host>\n'
    printf '    <status state="up" reason="syn-ack"/>\n'
    printf '    <address addr="%s" addrtype="%s"/>\n' "$ip" "$addrtype"
    printf '    <ports>\n'
    printf '      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>\n'
    printf '      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" tunnel="ssl"/></port>\n'
    printf '    </ports>\n'
    printf '  </host>\n'
done
printf '%s\n' '</nmaprun>'
