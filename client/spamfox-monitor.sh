#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPOSITORY='dgicloud/SPFBL'
REF='hadcloud-cpanel-installer'
BASE_URL="https://raw.githubusercontent.com/${REPOSITORY}/${REF}/client"

fail() { printf 'Instalador SpamFox: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || fail 'execute como root.'

if [[ -x /usr/local/cpanel/cpanel ]]; then
    PLATFORM=cpanel
    SCRIPT=spamfox-rspamd.cpanel.sh
elif command -v postconf >/dev/null 2>&1 && [[ -f /etc/postfix/main.cf ]]; then
    PLATFORM=postfix
    SCRIPT=spamfox-rspamd.postfix.sh
else
    fail 'não encontrei cPanel/Exim nem Postfix suportado.'
fi

command -v curl >/dev/null || command -v wget >/dev/null || fail 'instale curl ou wget.'
TEMP_SCRIPT=$(mktemp "/root/${SCRIPT}.XXXXXX")
cleanup() { rm -f -- "$TEMP_SCRIPT"; }
trap cleanup EXIT

if command -v curl >/dev/null; then
    curl --fail --silent --show-error --location --retry 2 "$BASE_URL/$SCRIPT" -o "$TEMP_SCRIPT" || fail 'download do instalador da plataforma falhou.'
else
    wget --https-only -q "$BASE_URL/$SCRIPT" -O "$TEMP_SCRIPT" || fail 'download do instalador da plataforma falhou.'
fi
chmod 0700 "$TEMP_SCRIPT"
bash "$TEMP_SCRIPT" "$@" || STATUS=$?
STATUS=${STATUS:-0}
cleanup
trap - EXIT
exit "$STATUS"
