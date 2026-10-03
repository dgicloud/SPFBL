#!/usr/bin/env bash
set -Eeuo pipefail

HERE=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)
SERVER=${HAD_SPFBL_HOST:-151.242.41.35}
PORT=${HAD_SPFBL_PORT:-9877}
ACTIVATE_ACL=0
TEST_RECIPIENT=""

usage() {
    cat <<'EOF'
Uso: install-client.sh [--server IP] [--port 9877] [--activate-acl --test-recipient EMAIL]

Instala o adapter HAD em MONITOR/fail-open e consulta diretamente o core central.
--activate-acl instala os hooks RCPT e DATA/HEADER em MONITOR; sem essa opção, o Exim não muda.
--test-recipient informa uma caixa local aceita pelo Exim para o smoke DATA sem entrega.
EOF
}
fail() { echo "HAD AntiSpam cPanel: $*" >&2; exit 1; }

while (($#)); do
    case "$1" in
        --server) [[ $# -ge 2 ]] || fail "--server requer um IP."; SERVER=$2; shift 2 ;;
        --port) [[ $# -ge 2 ]] || fail "--port requer uma porta."; PORT=$2; shift 2 ;;
        --activate-acl) ACTIVATE_ACL=1; shift ;;
        --test-recipient) [[ $# -ge 2 ]] || fail "--test-recipient requer um endereço local."; TEST_RECIPIENT=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "argumento desconhecido: $1" ;;
    esac
done

if (( ACTIVATE_ACL )) && [[ -z "$TEST_RECIPIENT" ]]; then
    fail "--activate-acl requer --test-recipient com uma caixa local aceita pelo Exim."
fi

[[ $(id -u) -eq 0 ]] || fail "execute como root."
[[ -x /usr/local/cpanel/scripts/buildeximconf ]] || fail "este servidor não parece executar cPanel."
command -v systemctl >/dev/null || fail "systemd não encontrado."
command -v python3 >/dev/null || fail "Python 3 não encontrado."
getent passwd mailnull >/dev/null || fail "usuário mailnull não encontrado."
getent group mail >/dev/null || fail "grupo mail não encontrado."
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT > 0 && PORT < 65536 )) || fail "porta inválida."
python3 - "$SERVER" <<'PY'
import ipaddress
import sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("HAD AntiSpam cPanel: --server deve ser IP literal.")
PY

for file in "$HERE/had_antispam_client.py" "$HERE/had_antispam_feedback.py" "$ROOT/integrations/common/spfbl_client.py" "$ROOT/integrations/common/technical_signals.py" "$HERE/had-antispam-client.service"; do
    [[ -r "$file" ]] || fail "arquivo de instalação ausente: $file"
done

# Test the WAN route before replacing the development tunnel/adapter.
python3 - "$SERVER" "$PORT" <<'PY'
import socket
import sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    with socket.create_connection((host, port), timeout=2.0) as connection:
        connection.settimeout(2.0)
        connection.sendall(b"VERSION\n")
        response = connection.recv(256).decode("iso-8859-1", "replace")
    if not response.startswith("SPFBL-"):
        raise RuntimeError("resposta VERSION inesperada: " + response[:100])
except Exception as exc:
    raise SystemExit("HAD AntiSpam cPanel: core central não acessível em %s:%s: %s" % (host, port, exc))
PY

STATE=/var/lib/had-antispam-client
[[ ! -e /etc/systemd/system/had-antispam-client.service ]] || fail "cliente HAD direto já instalado; use update-client.sh ou rollback-client.sh."
[[ ! -e /etc/had-antispam/client.conf ]] || fail "/etc/had-antispam/client.conf já existe; preservado, instalação cancelada."
FEEDBACK_CLI=/usr/local/sbin/had-antispam-feedback
[[ ! -e "$FEEDBACK_CLI" && ! -L "$FEEDBACK_CLI" ]] || fail "$FEEDBACK_CLI já existe; preservado, instalação cancelada."
install -d -o root -g root -m 0750 "$STATE" /etc/had-antispam /usr/local/libexec/had-antispam
chmod 0755 /usr/local/libexec/had-antispam
LIBEXEC=/usr/local/libexec/had-antispam
HAD_PREVIOUS_ENTRYPOINT=0
HAD_PREVIOUS_MODULE=0
HAD_PREVIOUS_SIGNALS_MODULE=0
HAD_METADATA_KEY_CREATED=0
HAD_INSTALLED_RCPT_ACL=0
HAD_INSTALLED_DATA_ACL=0
HAD_INSTALLED_FEEDBACK=0
if [[ -e "$LIBEXEC/had_antispam_client.py" ]]; then
    cp -a "$LIBEXEC/had_antispam_client.py" "$STATE/had_antispam_client.py.backup"
    HAD_PREVIOUS_ENTRYPOINT=1
fi
if [[ -e "$LIBEXEC/spfbl_client.py" ]]; then
    cp -a "$LIBEXEC/spfbl_client.py" "$STATE/spfbl_client.py.backup"
    HAD_PREVIOUS_MODULE=1
fi
if [[ -e "$LIBEXEC/technical_signals.py" ]]; then
    cp -a "$LIBEXEC/technical_signals.py" "$STATE/technical_signals.py.backup"
    HAD_PREVIOUS_SIGNALS_MODULE=1
fi
if [[ -e /etc/had-antispam/signals-hmac.key || -L /etc/had-antispam/signals-hmac.key ]]; then
    HAD_METADATA_KEY_CREATED=0
else
    HAD_METADATA_KEY_CREATED=1
fi
if systemctl is-active --quiet had-antispam-dev-adapter.service || systemctl is-enabled --quiet had-antispam-dev-adapter.service; then
    printf '%s\n' yes > "$STATE/restore-dev-stack"
fi

rollback() {
    local status=$?
    if (( status != 0 )); then
        if (( HAD_INSTALLED_DATA_ACL )); then
            python3 "$HERE/manage_exim_data_acl.py" uninstall >/dev/null 2>&1 || true
        fi
        if (( HAD_INSTALLED_RCPT_ACL )); then
            python3 "$HERE/manage_exim_acl.py" uninstall >/dev/null 2>&1 || true
        fi
        if (( HAD_INSTALLED_DATA_ACL || HAD_INSTALLED_RCPT_ACL )); then
            /usr/local/cpanel/scripts/restartsrv_exim >/dev/null 2>&1 || true
        fi
        systemctl disable --now had-antispam-client.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/had-antispam-client.service /etc/had-antispam/client.conf
        if (( HAD_PREVIOUS_ENTRYPOINT )); then
            cp -a "$STATE/had_antispam_client.py.backup" "$LIBEXEC/had_antispam_client.py"
        else
            rm -f "$LIBEXEC/had_antispam_client.py"
        fi
        if (( HAD_PREVIOUS_MODULE )); then
            cp -a "$STATE/spfbl_client.py.backup" "$LIBEXEC/spfbl_client.py"
        else
            rm -f "$LIBEXEC/spfbl_client.py"
        fi
        if (( HAD_PREVIOUS_SIGNALS_MODULE )); then
            cp -a "$STATE/technical_signals.py.backup" "$LIBEXEC/technical_signals.py"
        else
            rm -f "$LIBEXEC/technical_signals.py"
        fi
        if (( HAD_METADATA_KEY_CREATED )); then
            rm -f /etc/had-antispam/signals-hmac.key
        fi
        if (( HAD_INSTALLED_FEEDBACK )); then
            rm -f "$FEEDBACK_CLI"
            rm -f "$STATE/had-antispam-feedback.sha256"
        fi
        systemctl daemon-reload >/dev/null 2>&1 || true
        if [[ -e "$STATE/restore-dev-stack" ]]; then
            systemctl enable had-antispam-dev-tunnel.service had-antispam-dev-adapter.service >/dev/null 2>&1 || true
            systemctl start had-antispam-dev-tunnel.service had-antispam-dev-adapter.service >/dev/null 2>&1 || true
            rm -f "$STATE/restore-dev-stack"
        fi
        echo "Instalação direta falhou; cliente parcial removido e adapter/túnel de desenvolvimento restaurado quando estava habilitado." >&2
    fi
    exit "$status"
}
trap rollback EXIT

systemctl stop had-antispam-dev-adapter.service had-antispam-dev-tunnel.service >/dev/null 2>&1 || true
systemctl disable had-antispam-dev-adapter.service had-antispam-dev-tunnel.service >/dev/null 2>&1 || true
install -o root -g root -m 0644 "$HERE/had_antispam_client.py" /usr/local/libexec/had-antispam/had_antispam_client.py
install -o root -g root -m 0644 "$ROOT/integrations/common/spfbl_client.py" /usr/local/libexec/had-antispam/spfbl_client.py
install -o root -g root -m 0644 "$ROOT/integrations/common/technical_signals.py" /usr/local/libexec/had-antispam/technical_signals.py
chown root:mail /etc/had-antispam
chmod 0750 /etc/had-antispam
PYTHONPATH=/usr/local/libexec/had-antispam python3 -c 'from technical_signals import ensure_metadata_key; ensure_metadata_key()'
HAD_INSTALLED_FEEDBACK=1
install -o root -g root -m 0750 "$HERE/had_antispam_feedback.py" "$FEEDBACK_CLI"
sha256sum "$FEEDBACK_CLI" | awk '{print $1}' > "$STATE/had-antispam-feedback.sha256"
chown root:root "$STATE/had-antispam-feedback.sha256"
chmod 0600 "$STATE/had-antispam-feedback.sha256"
printf 'HAD_SPFBL_HOST=%s\nHAD_SPFBL_PORT=%s\n' "$SERVER" "$PORT" > /etc/had-antispam/client.conf
chown root:root /etc/had-antispam/client.conf
chmod 0600 /etc/had-antispam/client.conf
install -o root -g root -m 0644 "$HERE/had-antispam-client.service" /etc/systemd/system/had-antispam-client.service
systemctl daemon-reload
systemctl enable --now had-antispam-client.service
sleep 1
systemctl is-active --quiet had-antispam-client.service || fail "serviço adapter não ficou ativo."
[[ -S /run/had-antispam/monitor.sock ]] || fail "socket monitor não foi criado."

if (( ACTIVATE_ACL )); then
    RCPT_RESULT=$(python3 "$HERE/manage_exim_acl.py" install) || fail "hook RCPT não passou validação/rebuild/fake SMTP."
    [[ "$RCPT_RESULT" == "installed" ]] && HAD_INSTALLED_RCPT_ACL=1
    DATA_RESULT=$(python3 "$HERE/manage_exim_data_acl.py" install --test-recipient "$TEST_RECIPIENT") || fail "hook DATA/HEADER não passou validação/rebuild/fake SMTP."
    [[ "$DATA_RESULT" == "installed" ]] && HAD_INSTALLED_DATA_ACL=1
    /usr/local/cpanel/scripts/restartsrv_exim
    python3 "$HERE/manage_exim_acl.py" healthcheck >/dev/null
    python3 "$HERE/manage_exim_data_acl.py" healthcheck >/dev/null
fi

trap - EXIT
echo "Adapter HAD MONITOR consultando ${SERVER}:${PORT}; fail-open ativo."
echo "Hooks RCPT e DATA/HEADER permanecem em MONITOR; respostas SPFBL não alteram aceite Exim."
echo "Feedback manual: had-antispam-feedback {spam|ham} mensagem.eml | {report|dataset} - (stdin)"
echo "ADMIN TCP 9875 não é usado pelo cPanel. Para retornar ao túnel de homologação: bash $HERE/rollback-client.sh"
