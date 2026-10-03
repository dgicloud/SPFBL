#!/usr/bin/env bash
set -Eeuo pipefail
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
[[ $(id -u) -eq 0 ]] || { echo "Execute como root." >&2; exit 1; }
ACL_CHANGED=0
if [[ -f /var/lib/had-antispam/cpanel-data-acl/current/manifest.json ]]; then
    python3 "$HERE/manage_exim_data_acl.py" uninstall
    ACL_CHANGED=1
fi
if [[ -f /var/lib/had-antispam/cpanel-acl/current/manifest.json ]]; then
    python3 "$HERE/manage_exim_acl.py" uninstall
    ACL_CHANGED=1
fi
if (( ACL_CHANGED )); then
    /usr/local/cpanel/scripts/restartsrv_exim
fi
systemctl disable --now had-antispam-client.service >/dev/null 2>&1 || true
if [[ -e /var/lib/had-antispam-client/restore-dev-stack ]]; then
    systemctl enable had-antispam-dev-tunnel.service had-antispam-dev-adapter.service
    systemctl start had-antispam-dev-tunnel.service had-antispam-dev-adapter.service
    rm -f /var/lib/had-antispam-client/restore-dev-stack
    echo "Adapter/túnel de desenvolvimento restaurado."
else
    echo "Adapter HAD direto parado; não havia serviço de túnel anterior habilitado para restaurar."
fi
