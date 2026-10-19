#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
mkdir -p "$WORK/classes" "$WORK/runtime/data"
find "$ROOT/src" "$ROOT/test" -name '*.java' -print > "$WORK/sources.txt"
javac -encoding UTF-8 -source 8 -target 8 -cp "$ROOT/lib/*" -d "$WORK/classes" @"$WORK/sources.txt"
mkdir -p "$WORK/classes/net/spfbl/core"
cp "$ROOT"/src/net/spfbl/core/*.obj "$WORK/classes/net/spfbl/core/"
(cd "$WORK/runtime" && java -cp "$WORK/classes:$ROOT/lib/*" net.spfbl.data.ContentBayesSmoke)
(cd "$WORK/runtime" && java -cp "$WORK/classes:$ROOT/lib/*" net.spfbl.service.ServerSPFBLBayesPolicySmoke)
(cd "$WORK/runtime" && java -cp "$WORK/classes:$ROOT/lib/*" net.spfbl.service.BayesAdminMultipartSmoke)
(cd "$WORK/runtime" && java -cp "$WORK/classes:$ROOT/lib/*" net.spfbl.service.ServerSMTPArchiveSmoke)
(cd "$WORK/runtime" && java -cp "$WORK/classes:$ROOT/lib/*" net.spfbl.service.FirewallAdminSmoke "${SPAMFOX_FIREWALL_PREVIEW:-}")
(cd "$WORK/runtime" && java -cp "$WORK/classes:$ROOT/lib/*" net.spfbl.service.ClientRequestMetricsSmoke "${SPAMFOX_REQUESTS_PREVIEW:-}")
