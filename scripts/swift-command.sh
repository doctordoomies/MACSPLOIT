#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p build/ModuleCache build/swift-cache build/swift-config build/swift-security
export CLANG_MODULE_CACHE_PATH="$PWD/build/ModuleCache"
if [ "${1:-}" = test ]; then
    # Command Line Tools ship Swift Testing but SwiftPM may omit its framework path.
    developer_dir=$(xcode-select -p)
    for frameworks in "$developer_dir/Library/Developer/Frameworks" \
        "$developer_dir/Platforms/MacOSX.platform/Developer/Library/Frameworks"; do
        if [ -d "$frameworks/Testing.framework" ]; then
            set -- "$@" -Xswiftc -F -Xswiftc "$frameworks" \
                -Xlinker -F -Xlinker "$frameworks" -Xlinker -rpath -Xlinker "$frameworks"
            for testing_lib in "$developer_dir/Library/Developer/usr/lib" \
                "$developer_dir/Platforms/MacOSX.platform/Developer/usr/lib"; do
                if [ -f "$testing_lib/lib_TestingInterop.dylib" ]; then
                    set -- "$@" -Xlinker -rpath -Xlinker "$testing_lib"
                    break
                fi
            done
            break
        fi
    done
fi
exec swift "$@" --package-path apps/macos --scratch-path "$PWD/build/swift" \
    --cache-path "$PWD/build/swift-cache" --config-path "$PWD/build/swift-config" \
    --security-path "$PWD/build/swift-security" \
    -Xswiftc -module-cache-path -Xswiftc "$PWD/build/ModuleCache"
