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
cp apps/macos/Resources/MACSPLOIT-Logo.icns "$bundle/Contents/Resources/MACSPLOIT.icns"
cp apps/macos/Resources/MACSPLOIT-Logo-1024.png "$bundle/Contents/Resources/MACSPLOIT-Logo-1024.png"
codesign --force --sign - "$bundle/Contents/Helpers/macsploit-core"
# Sign the app with the virtualization entitlement so the optional managed Linux terminal
# can use Virtualization.framework. Ad-hoc signing carries the entitlement for local runs;
# public distribution to other users requires signing/notarizing with it.
codesign --force --sign - --entitlements apps/macos/Resources/MACSPLOIT.entitlements "$bundle"
codesign --verify --strict "$bundle"
printf 'Built %s\n' "$bundle"
