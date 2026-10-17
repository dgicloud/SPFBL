#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
    echo "usage: build-core.sh SOURCE_ROOT OUTPUT_ROOT" >&2
    exit 2
fi
SOURCE_ROOT=$1
OUTPUT_ROOT=$2
SOURCE_ROOT=$(cd -- "$SOURCE_ROOT" && pwd)
mkdir -p "$OUTPUT_ROOT/runtime" "$OUTPUT_ROOT/classes"
find "$SOURCE_ROOT/src" -name '*.java' -print > "$OUTPUT_ROOT/sources.txt"
javac -encoding UTF-8 -source 8 -target 8 \
    -cp "$SOURCE_ROOT/lib/*" \
    -d "$OUTPUT_ROOT/classes" \
    @"$OUTPUT_ROOT/sources.txt"
mkdir -p "$OUTPUT_ROOT/classes/net/spfbl/core"
cp "$SOURCE_ROOT/src/net/spfbl/core/"*.obj "$OUTPUT_ROOT/classes/net/spfbl/core/"
printf 'Manifest-Version: 1.0\nMain-Class: net.spfbl.core.Core\n\n' > "$OUTPUT_ROOT/MANIFEST.MF"
jar cfm "$OUTPUT_ROOT/runtime/SPFBL.jar" "$OUTPUT_ROOT/MANIFEST.MF" \
    -C "$OUTPUT_ROOT/classes" .
cp -a "$SOURCE_ROOT/lib" "$OUTPUT_ROOT/runtime/lib"
