#!/usr/bin/env bash
set -Eeuo pipefail

HERE=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)
LIBDIR=/usr/local/lib/had-content-scan
SERVICE=had-content-scan-gateway.service
UNIT_SOURCE="$ROOT/packaging/content-scan/$SERVICE"
UNIT_DEST="/etc/systemd/system/$SERVICE"
BACKUP_ROOT=/var/backups/had-antispam/content-scan
FILES=(scan_gateway.py scan_client.py spfbl_feedback.py spfbl_bayes.py
       manage_clients.py scan_report.py)

fail() { printf 'SpamFox gateway update: %s\n' "$*" >&2; exit 1; }
file_mode() {
    case "$1" in
        manage_clients.py|scan_report.py) printf '0755' ;;
        *) printf '0644' ;;
    esac
}
[[ $(id -u) -eq 0 ]] || fail 'execute como root.'
command -v systemctl >/dev/null || fail 'systemd não encontrado.'
command -v python3 >/dev/null || fail 'Python 3 não encontrado.'
[[ -d "$LIBDIR" ]] || fail "gateway não instalado em $LIBDIR."
systemctl is-active --quiet "$SERVICE" || fail 'gateway precisa estar ativo antes da atualização.'
[[ -r "$UNIT_SOURCE" ]] || fail "unit nativa ausente: $UNIT_SOURCE"

for file in "${FILES[@]}"; do
    [[ -r "$ROOT/integrations/content_scan/$file" ]] || fail "arquivo de origem ausente: $file"
    if [[ -e "$LIBDIR/$file" || -L "$LIBDIR/$file" ]]; then
        [[ -f "$LIBDIR/$file" && ! -L "$LIBDIR/$file" && -r "$LIBDIR/$file" ]] \
            || fail "arquivo instalado não regular ou não legível: $LIBDIR/$file"
    fi
done

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="$BACKUP_ROOT/$STAMP"
install -d -o root -g root -m 0700 "$BACKUP"
STAGE=$(mktemp -d /tmp/sfox-gateway-update.XXXXXX)
FILES_INSTALLED=0

rollback() {
    local status=$?
    if (( status != 0 && FILES_INSTALLED )); then
        printf 'Atualização falhou; restaurando arquivos anteriores. Backup: %s\n' "$BACKUP" >&2
        for file in "${FILES[@]}"; do
            if [[ -r "$BACKUP/$file" ]]; then
                install -o root -g root -m "$(file_mode "$file")" "$BACKUP/$file" "$LIBDIR/.$file.restore"
                mv -f "$LIBDIR/.$file.restore" "$LIBDIR/$file"
            elif [[ -e "$BACKUP/$file.absent" ]]; then
                rm -f -- "$LIBDIR/$file" "$LIBDIR/.$file.new" "$LIBDIR/.$file.restore"
            fi
        done
        if [[ -r "$BACKUP/$SERVICE" ]]; then
            install -o root -g root -m 0644 "$BACKUP/$SERVICE" "$UNIT_DEST.restore"
            mv -f "$UNIT_DEST.restore" "$UNIT_DEST"
        elif [[ -e "$BACKUP/$SERVICE.absent" ]]; then
            rm -f -- "$UNIT_DEST"
        fi
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart "$SERVICE" >/dev/null 2>&1 || true
    fi
    case "$STAGE" in
        /tmp/sfox-gateway-update.*) rm -rf -- "$STAGE" ;;
        *) printf 'Diretório temporário inesperado, preservado: %s\n' "$STAGE" >&2 ;;
    esac
    exit "$status"
}
trap rollback EXIT

for file in "${FILES[@]}"; do
    if [[ -f "$LIBDIR/$file" && ! -L "$LIBDIR/$file" ]]; then
        cp -a "$LIBDIR/$file" "$BACKUP/$file"
    else
        : > "$BACKUP/$file.absent"
    fi
    install -o root -g root -m "$(file_mode "$file")" "$ROOT/integrations/content_scan/$file" "$STAGE/$file"
done
if [[ -f "$UNIT_DEST" && ! -L "$UNIT_DEST" ]]; then
    cp -a "$UNIT_DEST" "$BACKUP/$SERVICE"
else
    : > "$BACKUP/$SERVICE.absent"
fi
python3 -m py_compile "$STAGE/scan_gateway.py" "$STAGE/scan_client.py" \
    "$STAGE/spfbl_feedback.py" "$STAGE/spfbl_bayes.py" \
    "$STAGE/manage_clients.py" "$STAGE/scan_report.py"

FILES_INSTALLED=1
for file in "${FILES[@]}"; do
    install -o root -g root -m "$(file_mode "$file")" "$STAGE/$file" "$LIBDIR/.$file.new"
    mv -f "$LIBDIR/.$file.new" "$LIBDIR/$file"
done
install -o root -g root -m 0644 "$UNIT_SOURCE" "$UNIT_DEST.new"
mv -f "$UNIT_DEST.new" "$UNIT_DEST"
systemctl daemon-reload
systemctl restart "$SERVICE"
systemctl is-active --quiet "$SERVICE" || fail 'gateway não permaneceu ativo após o restart.'
HEALTHY=0
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 2 http://127.0.0.1:11335/healthz >/dev/null 2>&1; then
        HEALTHY=1
        break
    fi
    sleep 0.25
done
[[ "$HEALTHY" -eq 1 ]] || fail 'health check do gateway falhou após o restart.'
trap - EXIT
case "$STAGE" in
    /tmp/sfox-gateway-update.*) rm -rf -- "$STAGE" ;;
    *) fail "diretório temporário inesperado, não removido: $STAGE" ;;
esac
printf 'Gateway atualizado e validado. Backup dos arquivos anteriores: %s\n' "$BACKUP"
printf 'Os coletores continuam em MONITOR; o gateway usa o Bayes nativo do core. Rspamd não é uma dependência deste serviço.\n'
