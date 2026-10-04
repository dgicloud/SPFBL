#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
exec /usr/bin/python3 "$HERE/postfix_content_scan_manager.py" healthcheck "$@"
