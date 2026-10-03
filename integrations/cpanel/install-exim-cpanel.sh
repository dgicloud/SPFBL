#!/usr/bin/env bash
set -Eeuo pipefail

HERE=$(cd -- "$(dirname -- "$0")" && pwd)
SERVER=151.242.41.35
PORT=9877
RECIPIENT=""
CHECK_ONLY=0

usage() {
    cat <<'EOF'
Uso: bash install.sh --test-recipient caixa@dominio.local [--check]
     [--server IP] [--port PORTA]

Instala o adapter e os hooks RCPT/DATA de coleta em MONITOR/fail-open.
Preserva as regras de bloqueio SPFBL existentes. Não ativa Jev nem instala
chave OpenRouter. --check valida requisitos e conexão, sem alterar o servidor.
Antes: cadastre o IP público no core SPFBL e na allowlist da VM.
EOF
}
fail() { echo "HAD cPanel: $*" >&2; exit 1; }
while (($#)); do
    case "$1" in
        --test-recipient) [[ $# -ge 2 ]] || fail "informe uma caixa local."; RECIPIENT=$2; shift 2 ;;
        --server) [[ $# -ge 2 ]] || fail "informe o IP."; SERVER=$2; shift 2 ;;
        --port) [[ $# -ge 2 ]] || fail "informe a porta."; PORT=$2; shift 2 ;;
        --check) CHECK_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "argumento desconhecido: $1" ;;
    esac
done
[[ -n "$RECIPIENT" ]] || fail "--test-recipient é obrigatório; o teste não entrega mensagem."
[[ $(id -u) -eq 0 ]] || fail "execute como root."
[[ -x /usr/local/cpanel/scripts/buildeximconf ]] || fail "cPanel não encontrado."
command -v python3 >/dev/null || fail "Python 3.6 ou superior é necessário."
command -v systemctl >/dev/null || fail "systemd não encontrado."
command -v exim >/dev/null || fail "Exim não encontrado."
getent passwd mailnull >/dev/null || fail "usuário mailnull ausente."
getent group mail >/dev/null || fail "grupo mail ausente."
[[ ! -e /etc/systemd/system/had-antispam-client.service && ! -e /etc/had-antispam/client.conf ]] || fail "cliente já instalado; não será sobrescrito. Use o procedimento de atualização com snapshot."
python3 - "$HERE" "$SERVER" "$PORT" "$RECIPIENT" <<'PY'
import ipaddress, socket, sys
if sys.version_info < (3, 6):
    raise SystemExit('Python 3.6 ou superior é necessário.')
sys.path.insert(0, sys.argv[1])
from manage_exim_data_acl import TEST_RECIPIENT_RE
ipaddress.ip_address(sys.argv[2])
port = int(sys.argv[3])
if not 0 < port < 65536:
    raise SystemExit('Porta inválida.')
if not TEST_RECIPIENT_RE.match(sys.argv[4]):
    raise SystemExit('Endereço de teste inválido.')
with socket.create_connection((sys.argv[2], port), timeout=3) as conn:
    conn.settimeout(3)
    conn.sendall(b'VERSION\n')
    if not conn.recv(256).startswith(b'SPFBL-'):
        raise SystemExit('Core não autorizou VERSION; confira CLIENT e firewall.')
print('PASS: Python, parâmetros e consulta VERSION ao core.')
PY
exim -bt "$RECIPIENT" >/dev/null || fail "Exim não roteia a caixa informada."
if ((CHECK_ONLY)); then
    echo "Pré-verificação concluída. A validação SMTP local completa ocorre durante a instalação."
    exit 0
fi
exec bash "$HERE/install-client.sh" --server "$SERVER" --port "$PORT" --activate-acl --test-recipient "$RECIPIENT"
