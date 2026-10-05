#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
./scripts/build-core.sh
./scripts/swift-command.sh build
swift_bin=$(./scripts/swift-command.sh build --show-bin-path)
bundle="$PWD/build/MACSPLOIT.app"
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Helpers" "$bundle/Contents/Resources"
cp "$swift_bin/MACSPLOIT" "$bundle/Contents/MacOS/MACSPLOIT"
cp target/debug/macsploit-core "$bundle/Contents/Helpers/macsploit-core"
cp apps/macos/Resources/Info.plist "$bundle/Contents/Info.plist"
cp apps/macos/Resources/MACSPLOIT.icns "$bundle/Contents/Resources/MACSPLOIT.icns"
cp apps/macos/Resources/MACSPLOIT-AppIcon-1024.png "$bundle/Contents/Resources/MACSPLOIT-AppIcon-1024.png"
codesign --force --sign - "$bundle/Contents/Helpers/macsploit-core"
codesign --force --sign - "$bundle"
codesign --verify --strict "$bundle"
printf 'Built %s\n' "$bundle"
