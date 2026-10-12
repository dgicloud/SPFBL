#!/usr/bin/env bash
# Migrate the managed cPanel/Exim content collector from HAD names to SFOX.
set -Eeuo pipefail
umask 077

HERE=$(cd -- "$(dirname -- "$0")" && pwd)
EXIM_LOCAL=/etc/exim.conf.local
OLD_TRANSPORT=had_sfox_content_pipe
NEW_TRANSPORT=sfox_content_pipe
OLD_OPTION=/usr/local/cpanel/etc/exim/sysfilter/options/had-antispam-content-scan
NEW_OPTION=/usr/local/cpanel/etc/exim/sysfilter/options/sfox-content-scan
OLD_CONFIG_DIR=/etc/had-content-scan
NEW_CONFIG_DIR=/etc/sfox-content-scan
OLD_CLIENT=/usr/local/libexec/had-antispam/scan_client.py
NEW_LIB_DIR=/usr/local/libexec/sfox-content-scan
NEW_CLIENT=$NEW_LIB_DIR/scan_client.py
OLD_LINK=/usr/local/sbin/had-antispam-content-scan
NEW_LINK=/usr/local/sbin/sfox-content-scan
OLD_LOCK=/run/lock/had-content-scan.lock
NEW_LOCK=/run/lock/sfox-content-scan.lock
BACKUP_ROOT=/var/backups/sfox-content-scan/cpanel

fail() { printf 'SpamFox cPanel migration: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || fail 'execute como root.'
[[ -x /usr/local/cpanel/scripts/buildeximconf && -x /usr/local/cpanel/scripts/restartsrv_exim ]] || fail 'cPanel/Exim não encontrado.'
[[ -r "$HERE/exim/sysfilter-content-scan.conf" && -r "$HERE/exim/transport-content-scan.conf" && -r "$HERE/../content_scan/scan_client.py" ]] || fail 'pacote de migração incompleto.'
[[ -f "$EXIM_LOCAL" ]] || fail "$EXIM_LOCAL ausente; não alterei nada."

if ! grep -q "system_filter_pipe_transport = $OLD_TRANSPORT" "$EXIM_LOCAL"; then
    if grep -q "system_filter_pipe_transport = $NEW_TRANSPORT" "$EXIM_LOCAL"; then
        printf 'SFOX cPanel já está configurado; nenhuma migração necessária.\n'
        exit 0
    fi
    fail 'transporte HAD esperado não foi encontrado; preservei a configuração.'
fi
grep -q "^$OLD_TRANSPORT:" "$EXIM_LOCAL" || fail 'bloco de transporte HAD esperado não foi encontrado.'
[[ -f "$OLD_OPTION" && -f "$OLD_CLIENT" && -f "$OLD_CONFIG_DIR/client.json" ]] || fail 'artefatos HAD incompletos; preservei os arquivos.'
[[ ! -e "$NEW_OPTION" && ! -e "$NEW_CONFIG_DIR" && ! -e "$NEW_LINK" ]] || fail 'destino SFOX já existe; preservei os arquivos.'

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="$BACKUP_ROOT/$STAMP"
install -d -o root -g root -m 0700 "$BACKUP"
cp -a "$EXIM_LOCAL" "$BACKUP/exim.conf.local"
cp -a "$OLD_OPTION" "$BACKUP/option"
cp -a "$OLD_CONFIG_DIR" "$BACKUP/config"
cp -a "$OLD_CLIENT" "$BACKUP/scan_client.py"
[[ ! -e "$OLD_LINK" ]] || cp -a "$OLD_LINK" "$BACKUP/client-link"
[[ ! -e "$OLD_LOCK" ]] || cp -a "$OLD_LOCK" "$BACKUP/lock"

rollback() {
    local status=$?
    if (( status != 0 )); then
        cp -a "$BACKUP/exim.conf.local" "$EXIM_LOCAL" || true
        rm -f "$NEW_OPTION" "$NEW_LINK" "$NEW_LOCK" || true
        rm -rf "$NEW_CONFIG_DIR" "$NEW_LIB_DIR" || true
        cp -a "$BACKUP/option" "$OLD_OPTION" || true
        cp -a "$BACKUP/config" "$OLD_CONFIG_DIR" || true
        cp -a "$BACKUP/scan_client.py" "$OLD_CLIENT" || true
        [[ ! -e "$BACKUP/client-link" ]] || cp -a "$BACKUP/client-link" "$OLD_LINK" || true
        [[ ! -e "$BACKUP/lock" ]] || cp -a "$BACKUP/lock" "$OLD_LOCK" || true
        /usr/local/cpanel/scripts/buildeximconf >/dev/null 2>&1 || true
        /usr/local/cpanel/scripts/restartsrv_exim >/dev/null 2>&1 || true
        printf 'Migração revertida; backup preservado em %s\n' "$BACKUP" >&2
    fi
    exit "$status"
}
trap rollback EXIT

python3 - "$EXIM_LOCAL" <<'PY'
import os, sys, tempfile
path=sys.argv[1]
data=open(path,'rb').read()
if data.count(b'system_filter_pipe_transport = had_sfox_content_pipe') != 1 or data.count(b'had_sfox_content_pipe:') != 1:
    raise SystemExit('configuração HAD inesperada ou duplicada')
data=data.replace(b'system_filter_pipe_transport = had_sfox_content_pipe', b'system_filter_pipe_transport = sfox_content_pipe')
data=data.replace(b'had_sfox_content_pipe:', b'sfox_content_pipe:')
data=data.replace(b'HAD_SFOX_', b'SFOX_')
fd,tmp=tempfile.mkstemp(prefix='.sfox-content-scan-',dir=os.path.dirname(path))
with os.fdopen(fd,'wb') as out:
    out.write(data); out.flush(); os.fsync(out.fileno())
os.chmod(tmp,0o644)
os.replace(tmp,path)
PY

install -d -o root -g root -m 0755 "$NEW_LIB_DIR"
install -o root -g root -m 0755 "$HERE/../content_scan/scan_client.py" "$NEW_CLIENT"
mv "$OLD_CONFIG_DIR" "$NEW_CONFIG_DIR"
mv "$OLD_OPTION" "$NEW_OPTION"
install -o root -g root -m 0644 "$HERE/exim/sysfilter-content-scan.conf" "$NEW_OPTION"
ln -s "$NEW_CLIENT" "$NEW_LINK"
if [[ -e "$OLD_LOCK" ]]; then mv "$OLD_LOCK" "$NEW_LOCK"; else install -m 0600 /dev/null "$NEW_LOCK"; fi

/usr/local/cpanel/scripts/buildeximconf
/usr/sbin/exim -bP system_filter_pipe_transport | grep -qx "system_filter_pipe_transport = $NEW_TRANSPORT" || fail 'rebuild não manteve o transporte SFOX.'
/usr/sbin/exim -bP transport "$NEW_TRANSPORT" | grep -q '^use_bsmtp$' || fail 'transporte SFOX não foi carregado corretamente.'
/usr/local/cpanel/scripts/restartsrv_exim
systemctl is-active --quiet exim || fail 'Exim não ficou ativo após a migração.'

rm -f "$OLD_LINK" "$OLD_LOCK"
trap - EXIT
printf 'Migração concluída: SFOX content scan ativo. Backup: %s\n' "$BACKUP"