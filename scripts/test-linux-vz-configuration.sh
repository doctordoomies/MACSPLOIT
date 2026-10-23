#!/bin/sh
# Optional local object-construction check; does not boot a VM or download media.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
if [ "$(uname -m)" != arm64 ]; then
    echo 'Real Kali ARM64 configuration check requires Apple Silicon.' >&2
    exit 1
fi
mkdir -p build/ModuleCache
swiftc -swift-version 5 -parse-as-library -target arm64-apple-macosx13.0 \
    -module-cache-path "$PWD/build/ModuleCache" \
    apps/macos/Sources/MACSPLOITKit/Models/LinuxTerminal.swift \
    apps/macos/Sources/MACSPLOITKit/CoreClient/LinuxEnvironmentBackend.swift \
    apps/macos/Sources/MACSPLOITKit/CoreClient/LinuxImageDownloader.swift \
    apps/macos/Sources/MACSPLOITKit/CoreClient/LinuxVMStorage.swift \
    apps/macos/Sources/MACSPLOITKit/CoreClient/VZLinuxEnvironmentBackend.swift \
    tests/linux-vz-configuration.swift -o build/linux-vz-configuration-check
codesign --force --sign - --entitlements apps/macos/Resources/MACSPLOIT.entitlements \
    build/linux-vz-configuration-check
codesign --verify --strict build/linux-vz-configuration-check
build/linux-vz-configuration-check
