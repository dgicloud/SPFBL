#!/usr/bin/env bash
set -Eeuo pipefail

HERE=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)
CLIENT_ID=""
ENDPOINT="https://matrix.hadcloud.srv.br/internal/sfox/scan"
TOKEN_FILE=""
CHECK_ONLY=0
FILTER_NAME=had-antispam-content-scan
FILTER_OPTION=/usr/local/cpanel/etc/exim/sysfilter/options/had-antispam-content-scan
CLIENT=/usr/local/libexec/had-antispam/scan_client.py
CLIENT_LINK=/usr/local/sbin/had-antispam-content-scan
CLIENT_CONFIG_DIR=/etc/had-content-scan
CLIENT_CONFIG=/etc/had-content-scan/client.json
LOCK=/run/lock/had-content-scan.lock
STATE=/var/lib/had-antispam-client/content-scan
INSTALLED_FILTER=0
INSTALLED_CLIENT=0
INSTALLED_CONFIG=0
INSTALLED_CONFIG_DIR=0
INSTALLED_LOCK=0
EXIM_REBUILT=0
EXIM_RESTARTED=0

fail() { printf 'HAD content scan cPanel: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Uso: install-content-scan.sh --client-id ID --token-file ARQUIVO [--endpoint HTTPS_URL] [--check]

O token deve estar em arquivo root-only; nunca o passe como argumento. O cliente
transmite a cópia unseen da mensagem já aceita, em blocos, sem criar arquivo .eml.
EOF
}

while (($#)); do
    case "$1" in
        --client-id) [[ $# -ge 2 ]] || fail '--client-id requer um valor.'; CLIENT_ID=$2; shift 2 ;;
        --endpoint) [[ $# -ge 2 ]] || fail '--endpoint requer uma URL.'; ENDPOINT=$2; shift 2 ;;
        --token-file) [[ $# -ge 2 ]] || fail '--token-file requer um arquivo.'; TOKEN_FILE=$2; shift 2 ;;
        --check) CHECK_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "argumento desconhecido: $1" ;;
    esac
done

[[ $(id -u) -eq 0 ]] || fail 'execute como root.'
[[ -x /usr/local/cpanel/scripts/buildeximconf ]] || fail 'cPanel/WHM não encontrado.'
[[ -x /usr/local/cpanel/scripts/restartsrv_exim ]] || fail 'reinício gerenciado do Exim não encontrado.'
[[ -x /usr/sbin/exim ]] || fail 'binário Exim não encontrado.'
command -v python3 >/dev/null || fail 'Python 3 não encontrado.'
command -v runuser >/dev/null || fail 'runuser não encontrado; não consigo testar as permissões do usuário de filtro Exim.'
[[ -d /usr/local/cpanel/etc/exim/sysfilter/options ]] || fail 'diretório de opções system-filter do cPanel não encontrado.'
[[ -r "$ROOT/integrations/content_scan/scan_client.py" ]] || fail 'scan_client.py ausente no pacote.'
[[ -r "$HERE/exim/sysfilter-content-scan.conf" ]] || fail 'snippet de system-filter ausente.'
[[ "$CLIENT_ID" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || fail 'client-id inválido; use letras minúsculas, números, ponto, hífen ou sublinhado.'
[[ "$ENDPOINT" == "https://matrix.hadcloud.srv.br/internal/sfox/scan" ]] || fail 'endpoint deve ser o HTTPS autorizado da HAD.'
[[ -n "$TOKEN_FILE" && -f "$TOKEN_FILE" ]] || fail '--token-file deve apontar para arquivo regular.'
TOKEN_MODE=$(stat -c '%a' "$TOKEN_FILE")
TOKEN_OWNER=$(stat -c '%u' "$TOKEN_FILE")
(( TOKEN_OWNER == 0 )) || fail 'o arquivo do token precisa pertencer a root.'
(( (8#$TOKEN_MODE & 077) == 0 )) || fail 'o arquivo do token deve ter modo 0600 ou mais restrito.'
[[ ! -e "$FILTER_OPTION" ]] || fail "$FILTER_OPTION já existe; preservado."
[[ ! -e "$CLIENT" && ! -e "$CLIENT_LINK" ]] || fail 'cliente existente foi preservado; remova ou atualize pelo procedimento próprio.'
[[ ! -e "$CLIENT_CONFIG" ]] || fail "$CLIENT_CONFIG já existe; preservado."
[[ ! -e "$STATE" ]] || fail "$STATE já existe; revise antes de instalar."
[[ ! -e "$LOCK" ]] || fail "$LOCK já existe; revise antes de instalar."

SYSTEM_FILTER=$(/usr/sbin/exim -bP system_filter 2>/dev/null | sed -n 's/^[^=]*= *//p' | head -n1)
FILTER_USER=$(/usr/sbin/exim -bP system_filter_user 2>/dev/null | sed -n 's/^[^=]*= *//p' | head -n1)
FILTER_GROUP=$(/usr/sbin/exim -bP system_filter_group 2>/dev/null | sed -n 's/^[^=]*= *//p' | head -n1)
PIPE_TRANSPORT=$(/usr/sbin/exim -bP system_filter_pipe_transport 2>/dev/null | sed -n 's/^[^=]*= *//p' | head -n1)
[[ -n "$SYSTEM_FILTER" && -r "$SYSTEM_FILTER" ]] || fail 'system_filter do Exim não está configurado ou legível.'
[[ -n "$FILTER_USER" ]] || FILTER_USER=mailnull
getent passwd "$FILTER_USER" >/dev/null || fail "usuário do system filter não encontrado: $FILTER_USER."
[[ -n "$FILTER_GROUP" ]] || FILTER_GROUP=$(id -gn "$FILTER_USER") || fail 'não consegui determinar o grupo do system filter.'
getent group "$FILTER_GROUP" >/dev/null || fail "grupo do system filter não encontrado: $FILTER_GROUP."
FILTER_GID=$(getent group "$FILTER_GROUP" | cut -d: -f3)
[[ -n "$PIPE_TRANSPORT" ]] || fail 'system_filter_pipe_transport não está configurado. No WHM, abra Service Configuration > Exim Configuration Manager > Advanced Editor > Add additional configuration setting, defina system_filter_pipe_transport = address_pipe, salve para reconstruir o Exim e execute o instalador novamente.'
[[ "$PIPE_TRANSPORT" == "address_pipe" ]] || fail "system_filter_pipe_transport está definido como '$PIPE_TRANSPORT'; este instalador exige o transporte pipe padrão do cPanel: address_pipe."

python3 - "$ENDPOINT" "$CLIENT_ID" <<'PY'
import sys
from urllib.parse import urlsplit
parsed = urlsplit(sys.argv[1])
if parsed.scheme != "https" or parsed.hostname != "matrix.hadcloud.srv.br" or parsed.path != "/internal/sfox/scan":
    raise SystemExit("endpoint HTTPS inválido")
try:
    sys.argv[2].encode("ascii")
except UnicodeEncodeError:
    raise SystemExit("client-id inválido")
if not sys.argv[2].islower():
    raise SystemExit("client-id inválido")
PY

python3 -m py_compile "$ROOT/integrations/content_scan/scan_client.py" || fail 'scan_client.py não compilou.'
python3 - "$ENDPOINT" <<'PY'
import http.client
import ssl
import sys
from urllib.parse import urlsplit
url = urlsplit(sys.argv[1])
connection = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=5,
                                         context=ssl.create_default_context())
try:
    connection.request("POST", url.path, body=b"", headers={"Content-Length": "0"})
    response = connection.getresponse()
    body = response.read(1024)
finally:
    connection.close()
if response.status != 403 or b'"error":"forbidden"' not in body:
    raise SystemExit("Nginx allowlist/gateway não respondeu com o 403 JSON esperado para token ausente")
PY

if (( CHECK_ONLY )); then
    printf 'Pré-verificação concluída; cliente, endpoint HTTPS, system_filter e transporte pipe estão disponíveis.\n'
    exit 0
fi

rollback() {
    local status=$?
    if (( status != 0 )); then
        if (( INSTALLED_FILTER )); then rm -f "$FILTER_OPTION"; fi
        if (( INSTALLED_CLIENT )); then rm -f "$CLIENT" "$CLIENT_LINK"; fi
        if (( INSTALLED_CONFIG )); then rm -f "$CLIENT_CONFIG"; fi
        if (( INSTALLED_LOCK )); then rm -f "$LOCK"; fi
        if (( INSTALLED_CONFIG_DIR )); then rmdir "$CLIENT_CONFIG_DIR" 2>/dev/null || true; fi
        if (( EXIM_REBUILT )); then /usr/local/cpanel/scripts/buildeximconf >/dev/null 2>&1 || true; fi
        if (( EXIM_REBUILT || EXIM_RESTARTED )); then /usr/local/cpanel/scripts/restartsrv_exim >/dev/null 2>&1 || true; fi
        rm -rf "$STATE"
        printf 'Instalação revertida; o adapter SPFBL e as ACLs anteriores não foram alterados.\n' >&2
    fi
    exit "$status"
}
trap rollback EXIT

install -d -o root -g root -m 0755 /usr/local/libexec/had-antispam
install -d -o root -g root -m 0755 /usr/local/sbin
if [[ -e "$CLIENT_CONFIG_DIR" ]]; then
    [[ -d "$CLIENT_CONFIG_DIR" && ! -L "$CLIENT_CONFIG_DIR" ]] || fail "$CLIENT_CONFIG_DIR existe e não é um diretório seguro; preservado."
    [[ $(stat -c '%u:%g:%a' "$CLIENT_CONFIG_DIR") == "0:$FILTER_GID:750" ]] || fail "$CLIENT_CONFIG_DIR precisa ser root:$FILTER_GROUP com modo 0750; foi preservado."
else
    install -d -o root -g "$FILTER_GROUP" -m 0750 "$CLIENT_CONFIG_DIR"
    INSTALLED_CONFIG_DIR=1
fi
install -d -o root -g root -m 0700 "$STATE"
INSTALLED_CLIENT=1
install -o root -g root -m 0755 "$ROOT/integrations/content_scan/scan_client.py" "$CLIENT"
ln -s "$CLIENT" "$CLIENT_LINK"

INSTALLED_CONFIG=1
python3 - "$ENDPOINT" "$CLIENT_ID" "$TOKEN_FILE" "$CLIENT_CONFIG" <<'PY'
import json
import os
import sys
import tempfile
endpoint, client_id, token_path, destination = sys.argv[1:]
with open(token_path, "r") as stream:
    token = stream.read().strip()
if len(token) < 40 or "\n" in token or "\r" in token:
    raise SystemExit("token inválido")
directory = os.path.dirname(destination)
fd, temporary = tempfile.mkstemp(prefix=".content-scan-", dir=directory)
try:
    with os.fdopen(fd, "w") as stream:
        json.dump({"endpoint": endpoint, "client_id": client_id, "token": token,
                   "max_bytes": 25 * 1024 * 1024, "timeout_seconds": 20}, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o640)
    os.replace(temporary, destination)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
chown root:"$FILTER_GROUP" "$CLIENT_CONFIG"
chmod 0640 "$CLIENT_CONFIG"
INSTALLED_LOCK=1
install -o "$FILTER_USER" -g "$FILTER_GROUP" -m 0600 /dev/null "$LOCK"
runuser -u "$FILTER_USER" -g "$FILTER_GROUP" -- python3 - "$CLIENT_CONFIG" "$LOCK" <<'PY'
import fcntl
import json
import os
import sys
config_path, lock_path = sys.argv[1:]
with open(config_path, "r") as stream:
    config = json.load(stream)
if not isinstance(config.get("token"), str) or len(config["token"]) < 40:
    raise SystemExit("filter user cannot read a valid client credential")
with open(lock_path, "a+") as lock:
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
PY
INSTALLED_FILTER=1
install -o root -g root -m 0644 "$HERE/exim/sysfilter-content-scan.conf" "$FILTER_OPTION"

EXIM_REBUILT=1
/usr/local/cpanel/scripts/buildeximconf
ACTIVE_SYSTEM_FILTER=$(/usr/sbin/exim -bP system_filter 2>/dev/null | sed -n 's/^[^=]*= *//p' | head -n1)
ACTIVE_PIPE_TRANSPORT=$(/usr/sbin/exim -bP system_filter_pipe_transport 2>/dev/null | sed -n 's/^[^=]*= *//p' | head -n1)
[[ -r "$ACTIVE_SYSTEM_FILTER" ]] || fail 'system_filter ficou ilegível após rebuild.'
[[ "$ACTIVE_PIPE_TRANSPORT" == "address_pipe" ]] || fail 'o rebuild cPanel não manteve system_filter_pipe_transport = address_pipe.'
printf 'From: sender@example.invalid\r\nSubject: synthetic\r\n\r\nbody\r\n' | \
    /usr/sbin/exim -bF "$ACTIVE_SYSTEM_FILTER" >/dev/null 2>&1 || fail 'validação -bF do system-filter falhou.'
EXIM_RESTARTED=1
/usr/local/cpanel/scripts/restartsrv_exim
systemctl is-active --quiet exim || fail 'Exim não ficou ativo após reinício.'

trap - EXIT
rm -rf "$STATE"
printf 'Coletor de conteúdo instalado em MONITOR: primeira tentativa, mensagens SMTP externas não autenticadas, cópia unseen.\n'
printf 'O cliente sai após fila RAM confirmar 202; resultados Rspamd não alteram aceite nem entrega.\n'
printf 'Para rollback, remova %s, reconstrua Exim e reinicie pelo script cPanel.\n' "$FILTER_OPTION"
