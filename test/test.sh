#!/usr/bin/env sh

set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: sh %s path-to-test-binary\n' "$0" >&2
    exit 2
fi
executable=$1

"zig-out/bin/moxi-start" "$executable"

while location=$("zig-out/bin/moxi-source"); do
    printf '%s\n' "$location"
    if ! "zig-out/bin/moxi-next"; then
        break
    fi
done
