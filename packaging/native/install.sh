#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "$0")" && pwd)
VERSION=$(cat "$ROOT/release/version")
APP=/opt/spfbl
RELEASES="$APP/releases"
NEW_RELEASE="$RELEASES/$VERSION"
ETC=/etc/spamfox
LEGACY_ETC=/etc/had-antispam
STATE=/var/lib/spamfox
LEGACY_STATE=/var/lib/had-antispam
LOGS=/var/log/spfbl
BACKUP_ROOT=/var/backups/spamfox
DNSBL_CONFIG="$ETC/dnsbl-link.nft"
DNSBL_DROPIN_DIR=/etc/systemd/system/spamfox-firewall.service.d
DNSBL_DROPIN="$DNSBL_DROPIN_DIR/dnsbl-link.conf"
LEGACY_DNSBL_DROPIN_DIR=/etc/systemd/system/had-antispam-firewall.service.d
LEGACY_DNSBL_DROPIN="$LEGACY_DNSBL_DROPIN_DIR/dnsbl-link.conf"
LIBEXEC=/usr/local/lib/spamfox
SBIN=/usr/local/sbin
OLD_RELEASE=""
LEGACY_STATE_MOVED=0
LEGACY_CORE_WAS_ACTIVE=0
LEGACY_CORE_INSTALLED=0
LEGACY_TIMER_WAS_ACTIVE=0
LEGACY_OBS_WAS_ACTIVE=0
LEGACY_FIREWALL_WAS_ACTIVE=0
SPAMFOX_CORE_WAS_ACTIVE=0
SPAMFOX_TIMER_WAS_ACTIVE=0
SPAMFOX_OBS_WAS_ACTIVE=0
SPAMFOX_FIREWALL_WAS_ACTIVE=0
SPAMFOX_FIREWALL_ADMIN_WAS_ACTIVE=0
SPAMFOX_FIREWALL_ADMIN_EXISTED=0
SPAMFOX_UNITS_EXISTED=0
FIREWALL_APPLY_ATTEMPTED=0
MIGRATION_BACKUP=""
OLD_CONFIG_LINK_WAS_SYMLINK=0
OLD_CONFIG_LINK_TARGET=""
STAMP=$(date -u +%Y%m%dT%H%M%SZ)-$$

fail() { echo "SpamFox install: $*" >&2; exit 1; }

rollback() {
    local status=$?
    if (( status != 0 )); then
        systemctl stop spamfox-core.service spamfox-store.service spamfox-store.timer \
            spamfox-observability.service spamfox-firewall-admin.service spamfox-firewall.service >/dev/null 2>&1 || true
        if (( FIREWALL_APPLY_ATTEMPTED )) && [[ -x "$NEW_RELEASE/firewall.py" ]]; then
            python3 "$NEW_RELEASE/firewall.py" remove >/dev/null 2>&1 || true
        fi
        if (( LEGACY_CORE_INSTALLED )) && id hadantispam >/dev/null 2>&1 \
            && getent group hadantispam >/dev/null; then
            chown root:hadantispam "$ETC" "$ETC/spfbl.conf" 2>/dev/null || true
            chown -R hadantispam:hadantispam "$LOGS" 2>/dev/null || true
        fi
        if (( LEGACY_STATE_MOVED )); then
            mv -- "$STATE" "$LEGACY_STATE" 2>/dev/null || true
            if id hadantispam >/dev/null 2>&1 && getent group hadantispam >/dev/null; then
                chown -R hadantispam:hadantispam "$LEGACY_STATE" 2>/dev/null || true
                ln -sfn "$LEGACY_STATE/data" "$APP/data" 2>/dev/null || true
                ln -sfn "$LEGACY_STATE/history" "$APP/history" 2>/dev/null || true
            fi
        fi
        if [[ -n "$OLD_RELEASE" && -d "$OLD_RELEASE" ]]; then
            ln -sfn "$OLD_RELEASE" "$APP/current"
            if (( OLD_CONFIG_LINK_WAS_SYMLINK )); then
                ln -sfn -- "$OLD_CONFIG_LINK_TARGET" "$APP/spfbl.conf" 2>/dev/null || true
            elif [[ -L "$APP/spfbl.conf" ]] && [[ $(readlink "$APP/spfbl.conf") == "$ETC/spfbl.conf" ]]; then
                rm -f -- "$APP/spfbl.conf"
            fi
            systemctl daemon-reload >/dev/null 2>&1 || true
            if (( LEGACY_FIREWALL_WAS_ACTIVE )); then
                systemctl restart had-antispam-firewall.service >/dev/null 2>&1 || true
            elif (( SPAMFOX_FIREWALL_WAS_ACTIVE )); then
                systemctl restart spamfox-firewall.service >/dev/null 2>&1 || true
            fi
            if (( LEGACY_CORE_WAS_ACTIVE )); then
                systemctl enable had-antispam-core.service >/dev/null 2>&1 || true
                systemctl start had-antispam-core.service >/dev/null 2>&1 || true
            fi
            if (( LEGACY_OBS_WAS_ACTIVE )); then
                systemctl enable had-antispam-observability.service >/dev/null 2>&1 || true
                systemctl restart had-antispam-observability.service >/dev/null 2>&1 || true
            fi
            if (( LEGACY_TIMER_WAS_ACTIVE )); then
                systemctl enable had-antispam-store.timer >/dev/null 2>&1 || true
                systemctl start had-antispam-store.timer >/dev/null 2>&1 || true
            fi
            if (( SPAMFOX_CORE_WAS_ACTIVE )); then
                systemctl start spamfox-core.service >/dev/null 2>&1 || true
            fi
            if (( SPAMFOX_OBS_WAS_ACTIVE )); then
                systemctl start spamfox-observability.service >/dev/null 2>&1 || true
            fi
            if (( SPAMFOX_TIMER_WAS_ACTIVE )); then
                systemctl start spamfox-store.timer >/dev/null 2>&1 || true
            fi
            if (( SPAMFOX_FIREWALL_ADMIN_WAS_ACTIVE )); then
                systemctl start spamfox-firewall-admin.service >/dev/null 2>&1 || true
            fi
        fi
        if (( ! SPAMFOX_FIREWALL_ADMIN_EXISTED )); then
            systemctl disable spamfox-firewall-admin.service >/dev/null 2>&1 || true
            rm -f /etc/systemd/system/spamfox-firewall-admin.service
        fi
        if (( ! SPAMFOX_UNITS_EXISTED )); then
            systemctl disable spamfox-core.service spamfox-firewall.service spamfox-store.timer \
                spamfox-observability.service >/dev/null 2>&1 || true
            rm -f /etc/systemd/system/spamfox-core.service /etc/systemd/system/spamfox-firewall.service \
                /etc/systemd/system/spamfox-observability.service /etc/systemd/system/spamfox-store.service \
                /etc/systemd/system/spamfox-store.timer
        fi
        systemctl daemon-reload >/dev/null 2>&1 || true
        echo "Instalação falhou; a release e o estado anteriores foram restaurados quando existiam." >&2
    fi
    exit "$status"
}

[[ $(id -u) -eq 0 ]] || fail "execute como root."
command -v systemctl >/dev/null || fail "systemd não encontrado."
command -v nft >/dev/null || fail "nftables não encontrado; o listener não será aberto sem allowlist."
command -v python3 >/dev/null || fail "Python 3 não encontrado."
[[ -r "$ROOT/release/SPFBL.jar" && -d "$ROOT/release/lib" ]] || fail "bundle inválido ou incompleto."

JAVA_VERSION=$(java -version 2>&1 | sed -n '1s/.*version "\([0-9]*\).*/\1/p')
[[ "$JAVA_VERSION" =~ ^[0-9]+$ ]] || fail "Java não encontrado ou versão não identificada."
(( JAVA_VERSION >= 11 )) || fail "Java 11 ou superior é necessário."

if [[ -L "$APP/current" ]]; then OLD_RELEASE=$(readlink -f "$APP/current")
elif [[ -e "$APP/current" ]]; then fail "$APP/current existe e não é um link simbólico; instalação cancelada."; fi
systemctl cat had-antispam-core.service >/dev/null 2>&1 && LEGACY_CORE_INSTALLED=1 || true
if [[ -L "$APP/spfbl.conf" ]]; then
    OLD_CONFIG_LINK_WAS_SYMLINK=1
    OLD_CONFIG_LINK_TARGET=$(readlink "$APP/spfbl.conf")
fi
systemctl is-active --quiet had-antispam-core.service && LEGACY_CORE_WAS_ACTIVE=1 || true
systemctl is-active --quiet had-antispam-store.timer && LEGACY_TIMER_WAS_ACTIVE=1 || true
systemctl is-active --quiet had-antispam-observability.service && LEGACY_OBS_WAS_ACTIVE=1 || true
systemctl is-active --quiet had-antispam-firewall.service && LEGACY_FIREWALL_WAS_ACTIVE=1 || true
systemctl is-active --quiet spamfox-core.service && SPAMFOX_CORE_WAS_ACTIVE=1 || true
systemctl is-active --quiet spamfox-store.timer && SPAMFOX_TIMER_WAS_ACTIVE=1 || true
systemctl is-active --quiet spamfox-observability.service && SPAMFOX_OBS_WAS_ACTIVE=1 || true
systemctl is-active --quiet spamfox-firewall.service && SPAMFOX_FIREWALL_WAS_ACTIVE=1 || true
systemctl is-active --quiet spamfox-firewall-admin.service && SPAMFOX_FIREWALL_ADMIN_WAS_ACTIVE=1 || true
[[ ! -e /etc/systemd/system/spamfox-firewall-admin.service ]] || SPAMFOX_FIREWALL_ADMIN_EXISTED=1
for unit in spamfox-core.service spamfox-firewall.service spamfox-observability.service spamfox-store.service spamfox-store.timer; do
    if [[ -e "/etc/systemd/system/$unit" ]]; then SPAMFOX_UNITS_EXISTED=1; break; fi
done
[[ ! -L "$STATE" && ! -L "$LEGACY_STATE" ]] || fail "diretórios de estado não podem ser links simbólicos; verifique os caminhos antes da migração."
if [[ -d "$LEGACY_STATE" && -d "$STATE" ]] \
    && find "$STATE" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    fail "estado legado e SpamFox coexistem; faça backup e resolva a origem única antes de atualizar."
fi
trap rollback EXIT
systemctl stop spamfox-firewall-admin.service >/dev/null 2>&1 || true

if (( LEGACY_CORE_WAS_ACTIVE || LEGACY_TIMER_WAS_ACTIVE || LEGACY_OBS_WAS_ACTIVE )); then
    systemctl stop had-antispam-store.timer had-antispam-store.service had-antispam-observability.service >/dev/null 2>&1 || true
fi
if (( LEGACY_CORE_WAS_ACTIVE )); then
    systemctl stop had-antispam-core.service || fail "não foi possível parar o core antigo com segurança."
fi
if (( SPAMFOX_CORE_WAS_ACTIVE || SPAMFOX_TIMER_WAS_ACTIVE || SPAMFOX_OBS_WAS_ACTIVE )); then
    systemctl stop spamfox-store.timer spamfox-store.service spamfox-observability.service >/dev/null 2>&1 || true
fi
if (( SPAMFOX_CORE_WAS_ACTIVE )); then
    systemctl stop spamfox-core.service || fail "não foi possível parar o core SpamFox com segurança."
fi

if ! getent group spamfox >/dev/null; then groupadd --system spamfox; fi
if ! id spamfox >/dev/null 2>&1; then
    useradd --system --gid spamfox --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin spamfox
fi
install -d -o root -g root -m 0755 "$APP" "$RELEASES"
install -d -o root -g spamfox -m 0750 "$ETC"
chown root:spamfox "$ETC"
chmod 0750 "$ETC"

# Migrate mutable state only when the new location is absent or empty. Do not
# merge two non-empty state trees: their ticket keys and reputation data must
# remain a single coherent SPFBL database.
if [[ -d "$LEGACY_STATE" ]]; then
    if [[ ! -d "$STATE" || -z "$(find "$STATE" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        command -v tar >/dev/null || fail "tar ausente; não migrarei estado sem backup."
        install -d -o root -g root -m 0700 /var/backups/spamfox
        chmod 0700 /var/backups/spamfox
        MIGRATION_BACKUP="/var/backups/spamfox/pre-path-migration-$STAMP.tar.gz"
        BACKUP_ITEMS=(var/lib/had-antispam)
        [[ ! -d /etc/spamfox ]] || BACKUP_ITEMS+=(etc/spamfox)
        [[ ! -d /etc/had-antispam ]] || BACKUP_ITEMS+=(etc/had-antispam)
        tar -C / -czf "$MIGRATION_BACKUP" "${BACKUP_ITEMS[@]}" \
            || fail "backup pré-migração falhou; estado legado foi preservado."
        chmod 0600 "$MIGRATION_BACKUP"
    fi
    if [[ -e "$STATE" ]]; then rmdir -- "$STATE"; fi
    mv -- "$LEGACY_STATE" "$STATE"
    LEGACY_STATE_MOVED=1
fi

[[ ! -L "$LOGS" ]] || fail "$LOGS não pode ser um link simbólico; verifique antes da instalação."
install -d -o spamfox -g spamfox -m 0750 "$STATE" "$STATE/data" "$STATE/history" "$LOGS"
chown -R spamfox:spamfox "$LOGS"
install -d -o root -g root -m 0755 "$LIBEXEC" "$SBIN"
install -d -o root -g root -m 0700 /var/backups/spamfox/firewall

# Migrate the core configuration without replacing values already managed at
# the SpamFox path. This also repairs the /opt/spfbl/spfbl.conf link on upgrade.
if [[ -d "$LEGACY_ETC" ]]; then
    if [[ ! -e "$ETC/spfbl.conf" && -f "$LEGACY_ETC/spfbl.conf" ]]; then
        install -o root -g spamfox -m 0640 "$LEGACY_ETC/spfbl.conf" "$ETC/spfbl.conf"
    fi
    if [[ ! -e "$ETC/allowed-cpanels.txt" && -f "$LEGACY_ETC/allowed-cpanels.txt" ]]; then
        install -o root -g root -m 0640 "$LEGACY_ETC/allowed-cpanels.txt" "$ETC/allowed-cpanels.txt"
    fi
    if [[ ! -e "$ETC/dnsbl-link.nft" && -f "$LEGACY_ETC/dnsbl-link.nft" ]]; then
        install -o root -g root -m 0640 "$LEGACY_ETC/dnsbl-link.nft" "$ETC/dnsbl-link.nft"
    fi
fi

# Keep the DNSBL URL redirect across the service rename and future reboots.
DNSBL_CONFIG_BACKUP=""
if [[ -f "$DNSBL_CONFIG" ]] && grep -Fq 'table inet had_antispam_dnsbl_link' "$DNSBL_CONFIG"; then
    install -d -o root -g root -m 0700 "$BACKUP_ROOT"
    DNSBL_CONFIG_BACKUP="$BACKUP_ROOT/dnsbl-link-pre-spamfox-$STAMP.nft"
    cp -a -- "$DNSBL_CONFIG" "$DNSBL_CONFIG_BACKUP"
    chmod 0600 "$DNSBL_CONFIG_BACKUP"
    DNSBL_TEMP=$(mktemp "$ETC/.dnsbl-link.XXXXXX")
    sed 's/table inet had_antispam_dnsbl_link/table inet spamfox_dnsbl_link/' "$DNSBL_CONFIG" > "$DNSBL_TEMP"
    chown root:root "$DNSBL_TEMP"
    chmod 0640 "$DNSBL_TEMP"
    mv -f -- "$DNSBL_TEMP" "$DNSBL_CONFIG"
fi

if [[ -f "$DNSBL_CONFIG" ]] && grep -Fq 'table inet spamfox_dnsbl_link' "$DNSBL_CONFIG"; then
    install -d -o root -g root -m 0755 "$DNSBL_DROPIN_DIR"
    if [[ -e "$DNSBL_DROPIN" ]] && ! cmp -s "$DNSBL_DROPIN" "$ROOT/native/spamfox-firewall-dnsbl-link.conf"; then
        fail "$DNSBL_DROPIN existe e diverge do drop-in gerenciado; arquivo preservado."
    fi
    install -o root -g root -m 0644 "$ROOT/native/spamfox-firewall-dnsbl-link.conf" "$DNSBL_DROPIN"
    NFT_CHECK=$(mktemp)
    if nft list table inet spamfox_dnsbl_link >/dev/null 2>&1; then
        printf '%s\n' 'delete table inet spamfox_dnsbl_link' > "$NFT_CHECK"
    fi
    cat "$DNSBL_CONFIG" >> "$NFT_CHECK"
    nft -c -f "$NFT_CHECK" || fail "configuração do redirecionamento DNSBL inválida; regras ativas preservadas."
    rm -f -- "$NFT_CHECK"
fi

if [[ ! -e "$STATE/data" || -z "$(find "$STATE/data" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    cp -a "$ROOT/release/data-seed/." "$STATE/data/"
fi
if [[ ! -e "$STATE/history" ]]; then install -d -o spamfox -g spamfox -m 0750 "$STATE/history"; fi
# JUnique stores its single-instance lock under HOME/.junique. A migrated state
# tree can contain HAD-owned hidden runtime files, so repair ownership across
# the complete SpamFox home before starting the JVM.
chown -R spamfox:spamfox "$STATE"
chmod 0750 "$STATE"

if [[ ! -e "$ETC/spfbl.conf" ]]; then install -o root -g spamfox -m 0640 "$ROOT/native/spfbl.conf" "$ETC/spfbl.conf"; fi
chown root:spamfox "$ETC/spfbl.conf"
chmod 0640 "$ETC/spfbl.conf"
if [[ ! -e "$ETC/allowed-cpanels.txt" ]]; then install -o root -g root -m 0640 "$ROOT/native/allowed-cpanels.txt" "$ETC/allowed-cpanels.txt"; fi
python3 - "$ETC/allowed-cpanels.txt" "$SPAMFOX_UNITS_EXISTED" <<'PY' || fail "allowlist vazia ou inválida; nenhum MTA será liberado."
import ipaddress
import sys

networks = []
for number, raw in enumerate(open(sys.argv[1]), 1):
    value = raw.split("#", 1)[0].strip()
    if not value:
        continue
    try:
        networks.append(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise SystemExit("invalid entry on line %d" % number)
if not networks and sys.argv[2] != "1":
    raise SystemExit("empty allowlist")
PY

if [[ -e "$NEW_RELEASE" ]]; then fail "release $VERSION já existe; escolha outra versão. sem sobrescrever arquivos instalados."; fi
install -d -o root -g root -m 0755 "$NEW_RELEASE"
cp -a "$ROOT/release/." "$NEW_RELEASE/"
install -o root -g root -m 0755 "$ROOT/native/control.py" "$NEW_RELEASE/control.py"
install -o root -g root -m 0755 "$ROOT/native/firewall.py" "$NEW_RELEASE/firewall.py"
install -o root -g root -m 0755 "$ROOT/native/observability.py" "$NEW_RELEASE/observability.py"
install -o root -g root -m 0755 "$ROOT/native/control.py" "$LIBEXEC/control.py"
install -o root -g root -m 0755 "$ROOT/native/backup_restore.py" "$LIBEXEC/backup_restore.py"
install -o root -g root -m 0755 "$ROOT/native/firewall.py" "$LIBEXEC/firewall.py"
install -o root -g root -m 0755 "$ROOT/native/firewall_admin.py" "$LIBEXEC/firewall_admin.py"
install -o root -g root -m 0755 "$ROOT/native/spamfox-backup" "$SBIN/spamfox-backup"
install -o root -g root -m 0755 "$ROOT/native/spamfox-restore" "$SBIN/spamfox-restore"
install -o root -g root -m 0755 "$ROOT/native/spamfox" "$NEW_RELEASE/spamfox"
chown -R root:root "$NEW_RELEASE"
chmod -R go-w "$NEW_RELEASE"

link_path() {
    local path=$1 target=$2
    if [[ -e "$path" && ! -L "$path" ]]; then fail "$path existe e não é um link gerenciado; instalação cancelada."; fi
    ln -sfn "$target" "$path"
}
link_path "$APP/current" "$NEW_RELEASE"
link_path "$APP/control.py" "$APP/current/control.py"
link_path "$APP/spfbl.conf" "$ETC/spfbl.conf"
link_path "$APP/data" "$STATE/data"
link_path "$APP/history" "$STATE/history"
link_path "$APP/web" "$APP/current/web"
link_path "$APP/template" "$APP/current/template"
link_path "$SBIN/spamfox" "$APP/current/spamfox"

install -o root -g root -m 0644 "$ROOT/native/spamfox-core.service" /etc/systemd/system/spamfox-core.service
install -o root -g root -m 0644 "$ROOT/native/spamfox-firewall.service" /etc/systemd/system/spamfox-firewall.service
install -o root -g root -m 0644 "$ROOT/native/spamfox-firewall-admin.service" /etc/systemd/system/spamfox-firewall-admin.service
install -o root -g root -m 0644 "$ROOT/native/spamfox-observability.service" /etc/systemd/system/spamfox-observability.service
install -o root -g root -m 0644 "$ROOT/native/spamfox-store.service" /etc/systemd/system/spamfox-store.service
install -o root -g root -m 0644 "$ROOT/native/spamfox-store.timer" /etc/systemd/system/spamfox-store.timer
systemctl daemon-reload
systemctl enable spamfox-firewall.service spamfox-firewall-admin.service spamfox-core.service spamfox-store.timer spamfox-observability.service >/dev/null
FIREWALL_APPLY_ATTEMPTED=1
systemctl restart spamfox-firewall.service
systemctl restart spamfox-firewall-admin.service
FIREWALL_ADMIN_READY=0
for attempt in $(seq 1 10); do
    if printf '%s\n' '{"action":"list"}' | python3 "$LIBEXEC/firewall_admin.py" \
        | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r.get("ok") and r.get("synchronized")' >/dev/null 2>&1; then
        FIREWALL_ADMIN_READY=1
        break
    fi
    sleep 1
done
[[ "$FIREWALL_ADMIN_READY" -eq 1 ]] || fail "gestão local do firewall não respondeu com regras sincronizadas."
if [[ -f "$DNSBL_CONFIG" ]] && grep -Fq 'table inet spamfox_dnsbl_link' "$DNSBL_CONFIG"; then
    nft list table inet spamfox_dnsbl_link >/dev/null \
        || fail "o redirecionamento DNSBL SpamFox não foi aplicado; regras antigas permanecem para rollback."
fi
systemctl restart spamfox-core.service
READY=0
for attempt in $(seq 1 300); do
    if systemctl is-active --quiet spamfox-core.service \
        && "$APP/current/control.py" version >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 2
done
[[ "$READY" -eq 1 ]] || fail "serviço nativo não respondeu VERSION em até 600 segundos."
systemctl start spamfox-store.timer
systemctl restart spamfox-observability.service
OBSERVABILITY_READY=0
for attempt in $(seq 1 15); do
    if python3 -c 'from urllib.request import urlopen; r=urlopen("http://127.0.0.1:9911/health", timeout=2); assert r.status == 200; assert b"\"status\": \"ok\"" in r.read(); r=urlopen("http://127.0.0.1:9911/metrics", timeout=2); assert b"spamfox_core_up 1" in r.read()' >/dev/null 2>&1; then
        OBSERVABILITY_READY=1
        break
    fi
    sleep 1
done
[[ "$OBSERVABILITY_READY" -eq 1 ]] || fail "serviço de observabilidade não respondeu /health e /metrics em até 15 segundos."

# Retire the legacy DNSBL redirect only after its SpamFox replacement is active.
if nft list table inet spamfox_dnsbl_link >/dev/null 2>&1; then
    systemctl stop had-antispam-firewall.service >/dev/null 2>&1 || true
    nft delete table inet had_antispam_dnsbl_link >/dev/null 2>&1 || true
    if [[ -f "$LEGACY_DNSBL_DROPIN" ]]; then
        install -d -o root -g root -m 0700 "$BACKUP_ROOT"
        LEGACY_DNSBL_BACKUP="$BACKUP_ROOT/legacy-dnsbl-link-dropin-$STAMP.conf"
        if cp -a -- "$LEGACY_DNSBL_DROPIN" "$LEGACY_DNSBL_BACKUP"; then
            chmod 0600 "$LEGACY_DNSBL_BACKUP"
            rm -f -- "$LEGACY_DNSBL_DROPIN"
            rmdir "$LEGACY_DNSBL_DROPIN_DIR" 2>/dev/null || true
            echo "Drop-in DNSBL legado arquivado em: $LEGACY_DNSBL_BACKUP"
        else
            echo "Aviso: não consegui arquivar $LEGACY_DNSBL_DROPIN; arquivo preservado." >&2
        fi
    fi
fi
if [[ -d "$STATE/rspamd-learning" ]] && ! systemctl is-active --quiet rspamd.service; then
    install -d -o root -g root -m 0700 "$BACKUP_ROOT"
    RSPAMD_ARCHIVE="$BACKUP_ROOT/retired-rspamd-learning-$STAMP"
    mv -- "$STATE/rspamd-learning" "$RSPAMD_ARCHIVE"
    chown -R root:root "$RSPAMD_ARCHIVE"
    echo "Dados legados do coletor Rspamd arquivados fora do estado ativo: $RSPAMD_ARCHIVE"
fi
# Once the replacement is healthy, disable and remove the prior unit files.
trap - EXIT
if [[ -d "$LEGACY_ETC" ]]; then
    install -d -o root -g root -m 0700 /var/backups/spamfox
    LEGACY_CONFIG_BACKUP="/var/backups/spamfox/legacy-config-$STAMP"
    if mv -- "$LEGACY_ETC" "$LEGACY_CONFIG_BACKUP"; then
        chmod 0700 "$LEGACY_CONFIG_BACKUP"
        echo "Configuração antiga arquivada em: $LEGACY_CONFIG_BACKUP"
    else
        echo "Aviso: preservei a configuração antiga em $LEGACY_ETC; arquive-a manualmente após validar o core." >&2
    fi
fi
systemctl disable had-antispam-core.service had-antispam-firewall.service \
    had-antispam-store.timer had-antispam-observability.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/had-antispam-core.service /etc/systemd/system/had-antispam-firewall.service \
    /etc/systemd/system/had-antispam-store.service /etc/systemd/system/had-antispam-store.timer \
    /etc/systemd/system/had-antispam-observability.service
systemctl daemon-reload >/dev/null 2>&1 || true
if [[ -L "$SBIN/had-antispam" ]] && [[ $(readlink "$SBIN/had-antispam") == "$APP/current/had-antispam" ]]; then
    rm -f -- "$SBIN/had-antispam"
fi
for legacy_command in "$SBIN/had-antispam-backup" "$SBIN/had-antispam-restore"; do
    if [[ -f "$legacy_command" ]] && grep -Fq '/usr/local/lib/had-antispam/backup_restore.py' "$legacy_command"; then
        rm -f -- "$legacy_command"
    fi
done
if [[ -f /usr/local/lib/had-antispam/control.py ]] \
    && grep -Fq 'had-antispam-core.service' /usr/local/lib/had-antispam/control.py; then
    rm -f -- /usr/local/lib/had-antispam/control.py
fi
if [[ -f /usr/local/lib/had-antispam/backup_restore.py ]] \
    && grep -Fq 'had-antispam-core.service' /usr/local/lib/had-antispam/backup_restore.py; then
    rm -f -- /usr/local/lib/had-antispam/backup_restore.py
fi
find /usr/local/lib/had-antispam -type f -name '*.pyc' -delete 2>/dev/null || true
find /usr/local/lib/had-antispam -type d -name __pycache__ -empty -delete 2>/dev/null || true
rmdir /usr/local/lib/had-antispam 2>/dev/null || true
[[ -z "$MIGRATION_BACKUP" ]] || echo "Backup anterior à migração: $MIGRATION_BACKUP"
[[ -z "$DNSBL_CONFIG_BACKUP" ]] || echo "Backup do DNSBL legado: $DNSBL_CONFIG_BACKUP"
echo "SpamFox $VERSION ativo. Consulta TCP 9877 protegida por /etc/spamfox/allowed-cpanels.txt; firewall bloqueia ADMIN 9875 e HTTP 8080 externamente."
echo "Para adicionar MTAs, inclua cada IP/CIDR na allowlist e execute: systemctl restart spamfox-firewall.service"
echo "Backup: spamfox-backup. Restore: spamfox-restore /var/backups/spamfox/ARQUIVO.tar.gz --dry-run; aplique com --yes."
echo "Status: spamfox status."
