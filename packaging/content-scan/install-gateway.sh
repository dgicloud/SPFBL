#!/usr/bin/env bash
set -Eeuo pipefail

HERE=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)
ALLOWLIST=/etc/had-antispam/allowed-cpanels.txt
CLIENT_CONFIG=/etc/had-antispam/content-scan-clients.json
LIBDIR=/usr/local/lib/had-content-scan
SERVICE=/etc/systemd/system/had-content-scan-gateway.service
NGINX_LOCATION=/etc/nginx/snippets/had-sfox-scan-location.conf
NGINX_ALLOW=/etc/nginx/snippets/had-sfox-scan-allow.conf

fail() { printf 'HAD content scan: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || fail 'execute como root.'
[[ -r /etc/os-release ]] || fail 'não consegui identificar o sistema operacional.'
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || fail 'este instalador requer Ubuntu 24.04.'
[[ -r "$ALLOWLIST" ]] || fail "allowlist cPanel ausente: $ALLOWLIST"
[[ -r "$ROOT/integrations/content_scan/scan_gateway.py" ]] || fail 'scan_gateway.py ausente.'
[[ -r "$ROOT/integrations/content_scan/manage_clients.py" ]] || fail 'manage_clients.py ausente.'
[[ -r "$ROOT/integrations/content_scan/install_nginx_location.py" ]] || fail 'gerenciador Nginx ausente.'
[[ ! -e "$SERVICE" ]] || fail 'gateway já instalado; use o fluxo de atualização, não sobrescreva a instalação.'
[[ ! -e "$NGINX_LOCATION" && ! -e "$NGINX_ALLOW" ]] || fail 'snippets Nginx existentes foram preservados; revise antes de continuar.'
[[ ! -e "$CLIENT_CONFIG" ]] || fail "$CLIENT_CONFIG já existe; instalação cancelada para preservar os clientes atuais."
[[ ! -e "$LIBDIR" ]] || fail "$LIBDIR já existe; instalação cancelada para preservar arquivos atuais."
[[ ! -e /usr/local/sbin/had-content-scan-clients && ! -e /usr/local/sbin/had-content-scan-sync-allowlist ]] || fail 'atalhos de administração já existem; arquivos preservados.'
systemctl is-active --quiet rspamd.service || fail 'Rspamd não está ativo.'
curl -fsS --max-time 2 http://127.0.0.1:11333/ping | grep -qi pong || fail 'Rspamd normal worker não respondeu.'
rspamd_config_test=$(rspamadm configtest 2>&1) || fail "$rspamd_config_test"
nginx -t >/dev/null 2>&1 || fail 'Nginx atual falha nginx -t; nada foi instalado.'

ALLOWLIST_COUNT=$(grep -cvE '^\s*(#|$)' "$ALLOWLIST" || true)
[[ "$ALLOWLIST_COUNT" -gt 0 ]] || fail 'allowlist cPanel está vazia.'
VHOST=$(python3 - "$ROOT/integrations/content_scan" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from install_nginx_location import find_enabled_vhost
print(find_enabled_vhost("matrix.hadcloud.srv.br"))
PY
)
VHOST_REAL=$(readlink -f "$VHOST")
VHOST_BACKUP="$VHOST_REAL.had-content-scan.bak"
[[ ! -e "$VHOST_BACKUP" ]] || fail "snapshot Nginx já existe e será preservado: $VHOST_BACKUP"

rollback() {
    local status=$?
    if (( status != 0 )); then
        systemctl disable --now had-content-scan-gateway.service >/dev/null 2>&1 || true
        rm -f "$SERVICE" /usr/local/sbin/had-content-scan-clients /usr/local/sbin/had-content-scan-sync-allowlist
        rm -f "$NGINX_LOCATION" "$NGINX_ALLOW" "$CLIENT_CONFIG"
        if [[ -f "$VHOST_BACKUP" ]]; then
            if cp -a "$VHOST_BACKUP" "$VHOST_REAL"; then
                rm -f "$VHOST_BACKUP"
            else
                printf 'ERRO: não consegui restaurar o vhost; snapshot preservado em %s\n' "$VHOST_BACKUP" >&2
            fi
        fi
        systemctl daemon-reload >/dev/null 2>&1 || true
        nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
        rm -rf "$LIBDIR"
        printf 'Instalação revertida; SPFBL, Exim e Postfix não foram alterados.\n' >&2
    fi
    exit "$status"
}
trap rollback EXIT

if ! getent group had-content-scan >/dev/null; then groupadd --system had-content-scan; fi
if ! getent passwd had-content-scan >/dev/null; then
    useradd --system --gid had-content-scan --home-dir /nonexistent --no-create-home \
        --shell /usr/sbin/nologin had-content-scan
fi
install -d -o root -g root -m 0755 "$LIBDIR"
install -d -o root -g had-content-scan -m 0750 /etc/had-antispam
install -d -o root -g root -m 0755 /etc/nginx/snippets
install -o root -g root -m 0644 "$ROOT/integrations/content_scan/scan_gateway.py" "$LIBDIR/scan_gateway.py"
install -o root -g root -m 0755 "$ROOT/integrations/content_scan/manage_clients.py" "$LIBDIR/manage_clients.py"
install -o root -g root -m 0755 "$ROOT/integrations/content_scan/sync_nginx_allowlist.py" "$LIBDIR/sync_nginx_allowlist.py"
install -o root -g root -m 0755 "$ROOT/integrations/content_scan/install_nginx_location.py" "$LIBDIR/install_nginx_location.py"
install -o root -g root -m 0644 "$HERE/had-content-scan-gateway.service" "$SERVICE"
install -o root -g root -m 0644 "$HERE/had-sfox-scan-location.conf" "$NGINX_LOCATION"
if [[ ! -e "$CLIENT_CONFIG" ]]; then
    printf '{"clients":{}}\n' > "$CLIENT_CONFIG"
    chown root:had-content-scan "$CLIENT_CONFIG"
    chmod 0640 "$CLIENT_CONFIG"
fi

python3 "$LIBDIR/sync_nginx_allowlist.py" --allowlist "$ALLOWLIST" --output "$NGINX_ALLOW"
python3 "$LIBDIR/install_nginx_location.py" --hostname matrix.hadcloud.srv.br
systemctl daemon-reload
systemctl enable --now had-content-scan-gateway.service
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 1 http://127.0.0.1:11335/healthz >/dev/null 2>&1; then break; fi
    sleep 0.25
done
curl -fsS --max-time 2 http://127.0.0.1:11335/healthz >/dev/null || fail 'gateway não respondeu ao health check.'
nginx -t || fail 'Nginx falhou após inclusão; restaure o backup do vhost antes de recarregar.'
systemctl reload nginx
systemctl is-active --quiet had-content-scan-gateway.service || fail 'gateway não ficou ativo.'

ln -sfn "$LIBDIR/manage_clients.py" /usr/local/sbin/had-content-scan-clients
ln -sfn "$LIBDIR/sync_nginx_allowlist.py" /usr/local/sbin/had-content-scan-sync-allowlist
trap - EXIT
printf 'Gateway ativo em 127.0.0.1:11335; Nginx aceita HTTPS somente dos IPs na allowlist cPanel.\n'
printf 'Fila: até 4 mensagens aguardando e 2 workers; payloads ficam somente em RAM.\n'
printf 'Rspamd continua em MONITOR; nenhuma decisão afeta Exim/Postfix.\n'
