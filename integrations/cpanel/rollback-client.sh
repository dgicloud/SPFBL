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
FEEDBACK_CLI=/usr/local/sbin/had-antispam-feedback
FEEDBACK_MANIFEST=/var/lib/had-antispam-client/had-antispam-feedback.sha256
if [[ -f "$FEEDBACK_CLI" && -f "$FEEDBACK_MANIFEST" ]]; then
    EXPECTED_FEEDBACK_HASH=$(cat "$FEEDBACK_MANIFEST")
    ACTUAL_FEEDBACK_HASH=$(sha256sum "$FEEDBACK_CLI" | awk '{print $1}')
    if [[ "$EXPECTED_FEEDBACK_HASH" =~ ^[a-f0-9]{64}$ && "$ACTUAL_FEEDBACK_HASH" == "$EXPECTED_FEEDBACK_HASH" ]]; then
        rm -f "$FEEDBACK_CLI"
        echo "Utilitário HAD de feedback removido."
    else
        echo "Utilitário de feedback foi alterado; arquivo preservado para revisão." >&2
    fi
    rm -f "$FEEDBACK_MANIFEST"
fi
if [[ -e /var/lib/had-antispam-client/restore-dev-stack ]]; then
    systemctl enable had-antispam-dev-tunnel.service had-antispam-dev-adapter.service
    systemctl start had-antispam-dev-tunnel.service had-antispam-dev-adapter.service
    rm -f /var/lib/had-antispam-client/restore-dev-stack
    echo "Adapter/túnel de desenvolvimento restaurado."
else
    echo "Adapter HAD direto parado; não havia serviço de túnel anterior habilitado para restaurar."
fi
