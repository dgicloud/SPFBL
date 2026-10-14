#!/usr/bin/env bash
# Installs the central Rspamd + Redis + HTTPS scanner gateway on the SpamFox VM.
set -Eeuo pipefail
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)

[[ $(id -u) -eq 0 ]] || { echo 'SpamFox Rspamd: execute como root.' >&2; exit 1; }
[[ -x "$ROOT/packaging/rspamd/install-local.sh" ]] || { echo 'SpamFox Rspamd: pacote incompleto.' >&2; exit 1; }
[[ -x "$ROOT/packaging/content-scan/install-gateway.sh" ]] || { echo 'SpamFox Rspamd: gateway ausente.' >&2; exit 1; }

case ${1:-install} in
  install)
    bash "$ROOT/packaging/rspamd/install-local.sh"
    bash "$ROOT/packaging/content-scan/install-gateway.sh"
    ;;
  rspamd-only) bash "$ROOT/packaging/rspamd/install-local.sh" ;;
  gateway-only) bash "$ROOT/packaging/content-scan/install-gateway.sh" ;;
  *)
    cat <<'EOF'
Uso: bash install-spamfox-rspamd.sh [install|rspamd-only|gateway-only]

install       instala Rspamd, Redis e o gateway HTTPS na VM central.
rspamd-only   instala somente Rspamd e Redis.
gateway-only  instala somente o gateway; exige Rspamd ativo e a allowlist SPFBL.
EOF
    exit 64
    ;;
esac