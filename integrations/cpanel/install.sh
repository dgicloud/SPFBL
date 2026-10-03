#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
exec /usr/bin/python3 "$HERE/manage_exim_acl.py" install "$@"
