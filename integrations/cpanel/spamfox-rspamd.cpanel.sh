#!/usr/bin/env bash
set -Eeuo pipefail

# Entry point for the optional Rspamd content collector. The native SPFBL
# installer remains client/spamfox.cpanel.sh and is intentionally untouched.
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ -r "$HERE/install-content-scan.sh" ]]; then
    INSTALLER="$HERE/install-content-scan.sh"
elif [[ -r "$HERE/integrations/cpanel/install-content-scan.sh" ]]; then
    INSTALLER="$HERE/integrations/cpanel/install-content-scan.sh"
else
    printf 'SpamFox Rspamd cPanel: pacote incompleto; install-content-scan.sh ausente.\n' >&2
    exit 1
fi

exec bash "$INSTALLER" "$@"
