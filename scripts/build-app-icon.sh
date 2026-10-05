#!/bin/sh
# Generate with native macOS tools; losslessly compress with Python stdlib.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
source_png="$PWD/apps/macos/Resources/MACSPLOIT-Logo-1024.png"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/macsploit-icon.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
iconset="$temporary/MACSPLOIT.iconset"
mkdir "$iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$source_png" --out "$iconset/icon_${size}x${size}.png" >/dev/null
    doubled=$((size * 2))
    if [ "$doubled" -eq 1024 ]; then
        # Copy the canonical image at its native size.
        cp "$source_png" "$iconset/icon_${size}x${size}@2x.png"
    else
        sips -z "$doubled" "$doubled" "$source_png" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
    fi
done
iconutil -c icns "$iconset" -o apps/macos/Resources/MACSPLOIT-Logo.icns

# iconutil re-encodes PNGs. Recompress their IDAT streams without changing pixels,
# metadata, icon representations, or alpha to stay within the repository size cap.
python3 - apps/macos/Resources/MACSPLOIT-Logo.icns <<'PYTHON'
import struct
import sys
import zlib
from pathlib import Path


def compress_png(data):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return data
    chunks, streams, offset = [], [], 8
    while offset < len(data):
        size, kind = struct.unpack(">I4s", data[offset:offset + 8])
        payload = data[offset + 8:offset + 8 + size]
        chunks.append((kind, payload))
        if kind == b"IDAT":
            streams.append(payload)
        offset += size + 12
    pixels = zlib.decompress(b"".join(streams))
    compressed = zlib.compress(pixels, 9)
    assert zlib.decompress(compressed) == pixels
    output, written = data[:8], False
    for kind, payload in chunks:
        if kind == b"IDAT":
            if written:
                continue
            payload, written = compressed, True
        output += (struct.pack(">I", len(payload)) + kind + payload
                   + struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff))
    return output if len(output) < len(data) else data


path = Path(sys.argv[1])
data = path.read_bytes()
assert data[:4] == b"icns" and int.from_bytes(data[4:8], "big") == len(data)
output, offset = b"", 8
while offset < len(data):
    kind, size = struct.unpack(">4sI", data[offset:offset + 8])
    payload = compress_png(data[offset + 8:offset + size])
    output += struct.pack(">4sI", kind, len(payload) + 8) + payload
    offset += size
path.write_bytes(b"icns" + struct.pack(">I", len(output) + 8) + output)
PYTHON
