#!/bin/sh
# Regenerate the reviewed app icon using only native macOS tools.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
source_png="$PWD/apps/macos/Resources/MACSPLOIT-AppIcon-1024.png"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/macsploit-icon.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
iconset="$temporary/MACSPLOIT.iconset"
mkdir "$iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$source_png" --out "$iconset/icon_${size}x${size}.png" >/dev/null
    doubled=$((size * 2))
    sips -z "$doubled" "$doubled" "$source_png" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o apps/macos/Resources/MACSPLOIT.icns
