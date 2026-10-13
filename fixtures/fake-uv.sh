#!/bin/sh
# Offline fake of the `uv` runtime for MACSPLOIT managed-Python install tests.
# NO network activity. Simulates:
#   uv --version                                   -> version banner
#   uv tool install --python <v> --force <pkg>==<ver>
#       writes an executable console script named after the package into
#       $UV_TOOL_BIN_DIR, like a real `uv tool install`, printing progress.
# Env knobs for tests:
#   FAKE_UV_FAIL=1   -> exit non-zero without installing (failure path)
#   FAKE_UV_SLEEP=N  -> sleep N seconds before installing (cancellation/timeout)
set -eu

for arg in "$@"; do
    case "$arg" in
        --version) echo "uv 0.13.0"; exit 0 ;;
    esac
done

[ "${1:-}" = "tool" ] && [ "${2:-}" = "install" ] || { echo "fake-uv: unexpected args: $*" >&2; exit 2; }

spec=""
for arg in "$@"; do
    case "$arg" in *==*) spec="$arg" ;; esac
done
[ -n "$spec" ] || { echo "fake-uv: no package==version spec" >&2; exit 2; }
[ -n "${UV_TOOL_BIN_DIR:-}" ] || { echo "fake-uv: UV_TOOL_BIN_DIR unset" >&2; exit 2; }

pkg=${spec%%==*}
case "$pkg" in
    sherlock-project) exe=sherlock ;;
    maigret) exe=maigret ;;
    socialscan) exe=socialscan ;;
    user-scanner) exe=user-scanner ;;
    *) echo "fake-uv: unknown package $pkg" >&2; exit 1 ;;
esac

echo "Resolved $spec"
echo "Using managed CPython (${UV_PYTHON_PREFERENCE:-default})"
[ -n "${FAKE_UV_SLEEP:-}" ] && sleep "$FAKE_UV_SLEEP"
if [ "${FAKE_UV_FAIL:-}" = "1" ]; then
    echo "error: simulated uv failure" >&2
    exit 1
fi

mkdir -p "$UV_TOOL_BIN_DIR"
printf '#!/bin/sh\necho "%s (fake managed install)"\n' "$exe" > "$UV_TOOL_BIN_DIR/$exe"
chmod 0755 "$UV_TOOL_BIN_DIR/$exe"
echo "Installed executable: $exe"
echo "Installed 1 tool"
