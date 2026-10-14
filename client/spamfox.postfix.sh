#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Installs the SpamFox SPFBL policy adapter for a Postfix host.
set -Eeuo pipefail
umask 077

REPOSITORY='dgicloud/SPFBL'
REF='hadcloud-cpanel-installer'
SERVER=${SFOX_SPFBL_HOST:-151.242.41.35}
PORT=${SFOX_SPFBL_PORT:-9877}
ROOT=$(mktemp -d /root/spamfox-postfix.XXXXXX)
cleanup() { rm -rf -- "$ROOT"; }
trap cleanup EXIT

fail() { printf 'SpamFox Postfix: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || fail 'execute como root.'
command -v postconf >/dev/null || fail 'Postfix nao foi encontrado.'
command -v curl >/dev/null || command -v wget >/dev/null || fail 'curl ou wget e necessario.'

fetch() {
    local remote=$1 local_path=$2
    if command -v curl >/dev/null; then
        curl -fsSL --retry 2 "https://raw.githubusercontent.com/${REPOSITORY}/${REF}/${remote}" -o "$local_path"
    else
        wget --https-only -q "https://raw.githubusercontent.com/${REPOSITORY}/${REF}/${remote}" -O "$local_path"
    fi
}

install -d -m 0755 "$ROOT/integrations/postfix" "$ROOT/integrations/common"
fetch integrations/postfix/install.sh "$ROOT/integrations/postfix/install.sh"
fetch integrations/postfix/manage_postfix.py "$ROOT/integrations/postfix/manage_postfix.py"
fetch integrations/postfix/postfix_policy.py "$ROOT/integrations/postfix/postfix_policy.py"
fetch integrations/common/spfbl_client.py "$ROOT/integrations/common/spfbl_client.py"
chmod 0755 "$ROOT/integrations/postfix/install.sh"

if [[ ${1:-} == '--check' ]]; then
    shift
    exec python3 "$ROOT/integrations/postfix/manage_postfix.py" validate --server "$SERVER" --port "$PORT" "$@"
fi
exec bash "$ROOT/integrations/postfix/install.sh" --server "$SERVER" --port "$PORT" --reload "$@"