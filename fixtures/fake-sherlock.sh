#!/bin/sh
# Offline fake of Sherlock for MACSPLOIT tests. NO network activity.
#   --version                              -> version banner
#   --csv --local --no-color --timeout N -- <username>
#       writes <username>.csv in the working directory, like upstream, only when
#       the "scan" finishes.
# Subjects select behavior deterministically:
#   octo-synthetic        -> GitHub Claimed, GitLab Available, Reddit WAF
#   malformed-synthetic   -> CSV missing required columns
#   noreport-synthetic    -> exits 0 without writing a report
#   failing-synthetic     -> exits 2 with an error on stderr, no report
#   slow-synthetic        -> sleeps (cancellation / timeout tests), no report
#   anything else         -> header only (zero results)
# Refuses (exit 64) if a prohibited mode is requested.
set -eu

for arg in "$@"; do
    case "$arg" in
        --version) echo "sherlock v0.15.0"; exit 0 ;;
        --nsfw|--proxy|--proxy=*|--tor|--tor-proxy) echo "fake-sherlock: prohibited $arg" >&2; exit 64 ;;
    esac
done

username=""; seen_sep=0; want_csv=0
for arg in "$@"; do
    if [ "$seen_sep" = "1" ] && [ -z "$username" ]; then username="$arg"; fi
    [ "$arg" = "--" ] && seen_sep=1
    [ "$arg" = "--csv" ] && want_csv=1
done
[ -n "$username" ] || { echo "fake-sherlock: no username" >&2; exit 2; }
[ "$want_csv" = "1" ] || { echo "fake-sherlock: expected --csv" >&2; exit 2; }

header="username,name,url_main,url_user,exists,http_status,response_time_s"
out="${username}.csv"

case "$username" in
    slow-synthetic) sleep 30 ;;
    noreport-synthetic) : ;;
    failing-synthetic) echo "Traceback: synthetic failure" >&2; exit 2 ;;
    malformed-synthetic) printf 'a,b,c\n1,2,3\n' > "$out" ;;
    octo-synthetic)
        {
            echo "$header"
            echo "octo-synthetic,GitHub,https://github.com,https://github.com/octo-synthetic,Claimed,200,0.41"
            echo "octo-synthetic,GitLab,https://gitlab.com,https://gitlab.com/octo-synthetic,Available,404,0.30"
            echo "octo-synthetic,Reddit,https://www.reddit.com,https://www.reddit.com/user/octo-synthetic,WAF,403,0.52"
        } > "$out" ;;
    *) echo "$header" > "$out" ;;
esac
echo "[*] Saved results to $out"
