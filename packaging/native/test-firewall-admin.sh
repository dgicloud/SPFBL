#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "$0")" && pwd)
command -v unshare >/dev/null
command -v nft >/dev/null
PARENT_NETNS=$(readlink /proc/self/ns/net)
exec unshare --user --map-root-user --net env SPAMFOX_ISOLATED_FIREWALL_TEST=1 \
    SPAMFOX_PARENT_NETNS="$PARENT_NETNS" PYTHONPATH="$ROOT" python3 "$ROOT/firewall_admin_smoke.py"
