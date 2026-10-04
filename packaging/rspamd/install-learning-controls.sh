#!/usr/bin/env bash
set -Eeuo pipefail

HERE=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(cd -- "$HERE/../.." && pwd)
OVERRIDE_SOURCE="$HERE/controller-lockdown.inc"
OVERRIDE_DEST=/etc/rspamd/override.d/worker-controller.inc
LIBDIR=/usr/local/lib/had-content-scan
LEARN_SOURCE="$ROOT/integrations/content_scan/learn_reviewed.py"
VERIFY_SOURCE="$ROOT/integrations/content_scan/verify_controller_access.py"
LEARN_DEST="$LIBDIR/learn_reviewed.py"
VERIFY_DEST="$LIBDIR/verify_controller_access.py"
LEARN_LINK=/usr/local/sbin/had-rspamd-learn
SECRET=/etc/had-antispam/rspamd-controller.secret
AUDIT_DIR=/var/lib/had-antispam/rspamd-learning
AUDIT_PATH="$AUDIT_DIR/training.jsonl"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/var/backups/had-antispam/rspamd/learning-controls-$STAMP
OVERRIDE_WAS_PRESENT=0
INSTALLED_LEARN=0
INSTALLED_VERIFY=0
INSTALLED_LINK=0
SERVICE_RESTARTED=0
OVERRIDE_CHANGED=0

fail() { printf 'HAD Rspamd learning: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || fail 'execute como root.'
[[ -r "$OVERRIDE_SOURCE" && -r "$LEARN_SOURCE" && -r "$VERIFY_SOURCE" ]] || fail 'arquivos do pacote incompletos.'
command -v rspamadm >/dev/null || fail 'Rspamd não está instalado.'
systemctl is-active --quiet rspamd.service || fail 'Rspamd não está ativo.'
[[ -f "$SECRET" && $(stat -c '%u:%a' "$SECRET") == '0:600' ]] || fail 'segredo do controller deve ser root:root 0600.'
[[ ! -e "$LEARN_DEST" && ! -e "$VERIFY_DEST" && ! -e "$LEARN_LINK" ]] || fail 'utilitário de aprendizagem já existe; atualização manual requerida.'
if [[ -e "$OVERRIDE_DEST" ]]; then
    grep -qF '# HAD-ANTISPAM-RSPAMD-MANAGED' "$OVERRIDE_DEST" || fail "$OVERRIDE_DEST contém configuração não gerenciada; nada foi sobrescrito."
    OVERRIDE_WAS_PRESENT=1
fi
if [[ -d "$AUDIT_DIR" ]]; then
    [[ $(stat -c '%u:%a' "$AUDIT_DIR") == '0:700' ]] || fail "$AUDIT_DIR deve ser root:root 0700."
else
    install -d -o root -g root -m 0700 "$AUDIT_DIR"
fi

install -d -o root -g root -m 0700 "$BACKUP"
[[ ! -e "$BACKUP/worker-controller.inc" ]] || fail "snapshot já existe e será preservado: $BACKUP/worker-controller.inc"
if (( OVERRIDE_WAS_PRESENT )); then cp -a "$OVERRIDE_DEST" "$BACKUP/worker-controller.inc"; fi

rollback() {
    local status=$?
    if (( status != 0 )); then
        (( INSTALLED_LINK )) && rm -f "$LEARN_LINK"
        (( INSTALLED_LEARN )) && rm -f "$LEARN_DEST"
        (( INSTALLED_VERIFY )) && rm -f "$VERIFY_DEST"
        if (( OVERRIDE_WAS_PRESENT )); then
            cp -a "$BACKUP/worker-controller.inc" "$OVERRIDE_DEST" || printf 'ERRO: snapshot preservado em %s\n' "$BACKUP" >&2
        else
            rm -f "$OVERRIDE_DEST"
        fi
        if (( SERVICE_RESTARTED )); then
            rspamadm configtest >/dev/null 2>&1 && systemctl restart rspamd.service >/dev/null 2>&1 || true
        fi
        printf 'Alteração de aprendizagem revertida quando possível; snapshot: %s\n' "$BACKUP" >&2
    fi
    exit "$status"
}
trap rollback EXIT

install -d -o root -g root -m 0755 /etc/rspamd/override.d "$LIBDIR" /usr/local/sbin
if ! cmp -s "$OVERRIDE_SOURCE" "$OVERRIDE_DEST"; then
    install -o root -g root -m 0644 "$OVERRIDE_SOURCE" "$OVERRIDE_DEST"
    OVERRIDE_CHANGED=1
fi
install -o root -g root -m 0755 "$LEARN_SOURCE" "$LEARN_DEST"
INSTALLED_LEARN=1
install -o root -g root -m 0755 "$VERIFY_SOURCE" "$VERIFY_DEST"
INSTALLED_VERIFY=1
ln -s "$LEARN_DEST" "$LEARN_LINK"
INSTALLED_LINK=1

rspamd_config=$(rspamadm configdump 2>/dev/null) || fail 'não consegui carregar a configuração efetiva.'
grep -Fq 'secure_ip []' <<<"$rspamd_config" || fail 'secure_ip vazio não aparece na configuração Rspamd.'
grep -Fq 'allow_file_and_shm_inputs = false;' <<<"$rspamd_config" || fail 'inputs File/Shm continuam ativos no controller.'
rspamadm configtest
if (( OVERRIDE_CHANGED )); then
    SERVICE_RESTARTED=1
    systemctl restart rspamd.service
else
    printf 'Override já está efetivo; reinício do Rspamd dispensado.\n'
fi
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 1 http://127.0.0.1:11333/ping 2>/dev/null | grep -qi pong; then break; fi
    sleep 0.5
done
curl -fsS --max-time 2 http://127.0.0.1:11333/ping | grep -qi pong || fail 'Rspamd normal worker não recuperou após reinício.'
python3 "$VERIFY_DEST" --secret "$SECRET" || fail 'controller não passou validação de credenciais privilegiadas.'
python3 "$LEARN_DEST" stats || fail 'rspamc stat não retornou as métricas de Bayes.'

trap - EXIT
printf 'CLI instalada: had-rspamd-learn. O controller exige senha e rejeita fontes File/Shm.\n'
printf 'Nenhuma amostra foi aprendida durante a instalação.\n'
printf 'Auditoria: %s (sem caminho, remetente, assunto ou corpo).\n' "$AUDIT_PATH"
printf 'Snapshot: %s\n' "$BACKUP"
