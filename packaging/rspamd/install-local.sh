#!/usr/bin/env bash
set -Eeuo pipefail

MARKER="# HAD-ANTISPAM-RSPAMD-MANAGED"
BACKUP_ROOT=/var/backups/had-antispam/rspamd
CONFIG_DIR=/etc/rspamd/local.d
REDIS_CONFIG=/etc/redis/redis.conf
REDIS_EXTRA=/etc/redis/had-antispam.conf
HAD_CONFIG=/etc/had-antispam

fail() { printf 'HAD Rspamd: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || fail 'execute como root.'
[[ -r /etc/os-release ]] || fail 'não consegui identificar a distribuição.'
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || fail 'este instalador foi preparado para Ubuntu 24.04.'
command -v systemctl >/dev/null || fail 'systemd não encontrado.'

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="$BACKUP_ROOT/$STAMP"
install -d -o root -g root -m 0700 "$BACKUP"
declare -A FILE_STATES=()
RSPAMD_WAS_ACTIVE=0
REDIS_WAS_ACTIVE=0
RSPAMD_WAS_ENABLED=0
REDIS_WAS_ENABLED=0
systemctl is-active --quiet rspamd.service && RSPAMD_WAS_ACTIVE=1 || true
systemctl is-active --quiet redis-server.service && REDIS_WAS_ACTIVE=1 || true
systemctl is-enabled --quiet rspamd.service && RSPAMD_WAS_ENABLED=1 || true
systemctl is-enabled --quiet redis-server.service && REDIS_WAS_ENABLED=1 || true

rollback() {
    local status=$?
    local path original
    if (( status != 0 )); then
        for path in "${!FILE_STATES[@]}"; do
            original="$BACKUP${path}"
            if [[ ${FILE_STATES[$path]} == 1 && -e "$original" ]]; then
                cp -a "$original" "$path"
            elif [[ ${FILE_STATES[$path]} == 0 ]]; then
                rm -f "$path"
            fi
        done
        systemctl daemon-reload >/dev/null 2>&1 || true
        if (( REDIS_WAS_ACTIVE )); then systemctl restart redis-server.service >/dev/null 2>&1 || true; else systemctl stop redis-server.service >/dev/null 2>&1 || true; fi
        if (( RSPAMD_WAS_ACTIVE )); then systemctl restart rspamd.service >/dev/null 2>&1 || true; else systemctl stop rspamd.service >/dev/null 2>&1 || true; fi
        if (( REDIS_WAS_ENABLED )); then systemctl enable redis-server.service >/dev/null 2>&1 || true; else systemctl disable redis-server.service >/dev/null 2>&1 || true; fi
        if (( RSPAMD_WAS_ENABLED )); then systemctl enable rspamd.service >/dev/null 2>&1 || true; else systemctl disable rspamd.service >/dev/null 2>&1 || true; fi
        printf 'Instalação Rspamd falhou; configuração anterior restaurada quando existia. Cópia de segurança: %s\n' "$BACKUP" >&2
    fi
    exit "$status"
}
trap rollback EXIT

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg
install -d -o root -g root -m 0755 /etc/apt/keyrings
curl -fsSL https://rspamd.com/apt-stable/gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/rspamd.gpg
chmod 0644 /etc/apt/keyrings/rspamd.gpg
printf 'deb [signed-by=/etc/apt/keyrings/rspamd.gpg] https://rspamd.com/apt-stable/ %s main\n' "$VERSION_CODENAME" > /etc/apt/sources.list.d/rspamd.list
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y rspamd redis-server

command -v rspamadm >/dev/null || fail 'rspamadm não foi instalado.'
command -v redis-server >/dev/null || fail 'redis-server não foi instalado.'
install -d -o root -g root -m 0755 "$CONFIG_DIR" /etc/rspamd/override.d
install -d -o root -g root -m 0755 /etc/redis
install -d -o root -g root -m 0755 "$HAD_CONFIG"

managed_or_empty() {
    local path=$1
    if [[ -v FILE_STATES[$path] ]]; then return; fi
    if [[ -e "$path" ]]; then FILE_STATES[$path]=1; else FILE_STATES[$path]=0; fi
    if [[ -e "$path" ]] && ! grep -qF "$MARKER" "$path"; then
        cp -a --parents "$path" "$BACKUP"
        fail "$path já contém configuração não gerenciada; cópia preservada em $BACKUP. Nada foi sobrescrito."
    fi
    if [[ -e "$path" ]]; then cp -a --parents "$path" "$BACKUP"; fi
}

write_managed() {
    local path=$1 mode=$2
    managed_or_empty "$path"
    install -d -o root -g root -m 0755 "$(dirname "$path")"
    local tmp
    tmp=$(mktemp "${path}.had.XXXXXX")
    cat > "$tmp"
    chown root:root "$tmp"
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$path"
}

write_managed "$CONFIG_DIR/redis.conf" 0644 <<'EOF'
# HAD-ANTISPAM-RSPAMD-MANAGED
servers = "127.0.0.1:6379";
timeout = 1s;
EOF

write_managed "$CONFIG_DIR/classifier-bayes.conf" 0644 <<'EOF'
# HAD-ANTISPAM-RSPAMD-MANAGED
new_schema = true;
backend = "redis";
min_tokens = 11;
min_learns = 200;
# Training is reserved for operator-reviewed SPAM/HAM; classifier predictions do not train themselves.
autolearn = "return function(task) return nil end";
EOF

write_managed "$CONFIG_DIR/worker-normal.inc" 0644 <<'EOF'
# HAD-ANTISPAM-RSPAMD-MANAGED
bind_socket = "127.0.0.1:11333";
count = 2;
EOF

write_managed "$CONFIG_DIR/options.inc" 0644 <<'EOF'
# HAD-ANTISPAM-RSPAMD-MANAGED
max_message = 25M;
task_timeout = 12s;
EOF

if [[ ! -r "$HAD_CONFIG/rspamd-controller.secret" ]]; then
    umask 077
    openssl rand -hex 32 > "$HAD_CONFIG/rspamd-controller.secret"
    chown root:root "$HAD_CONFIG/rspamd-controller.secret"
    chmod 0600 "$HAD_CONFIG/rspamd-controller.secret"
fi
CONTROLLER_SECRET=$(cat "$HAD_CONFIG/rspamd-controller.secret")
[[ ${#CONTROLLER_SECRET} -ge 64 ]] || fail 'segredo local do controller inválido; arquivo preservado para revisão.'
CONTROLLER_HASH=$(rspamadm pw -q -p "$CONTROLLER_SECRET")
[[ "$CONTROLLER_HASH" == \$* ]] || fail 'rspamadm não gerou hash de controller válido.'
write_managed "$CONFIG_DIR/worker-controller.inc" 0644 <<EOF
$MARKER
bind_socket = "127.0.0.1:11334";
password = "$CONTROLLER_HASH";
enable_password = "$CONTROLLER_HASH";
EOF
unset CONTROLLER_SECRET CONTROLLER_HASH

write_managed "$CONFIG_DIR/logging.inc" 0644 <<'EOF'
# HAD-ANTISPAM-RSPAMD-MANAGED
level = "notice";
log_format =<<EOD
result: $is_spam ($action), score: [$scores], symbols: [$symbols], bytes: $len, ms: $time_real
EOD
EOF

write_managed "$REDIS_EXTRA" 0644 <<'EOF'
# HAD-ANTISPAM-RSPAMD-MANAGED
bind 127.0.0.1 ::1
protected-mode yes
maxmemory 512mb
maxmemory-policy noeviction
appendonly yes
appendfsync everysec
EOF

if [[ ! -v FILE_STATES[$REDIS_CONFIG] ]]; then
    if [[ -e "$REDIS_CONFIG" ]]; then FILE_STATES[$REDIS_CONFIG]=1; else FILE_STATES[$REDIS_CONFIG]=0; fi
    cp -a --parents "$REDIS_CONFIG" "$BACKUP"
fi
if ! grep -qF 'include /etc/redis/had-antispam.conf' "$REDIS_CONFIG"; then
    printf '\n# HAD-ANTISPAM-RSPAMD-MANAGED\ninclude /etc/redis/had-antispam.conf\n' >> "$REDIS_CONFIG"
fi

write_managed /etc/systemd/system/rspamd.service.d/10-had-antispam.conf 0644 <<'EOF'
# HAD-ANTISPAM-RSPAMD-MANAGED
[Service]
CPUWeight=50
MemoryHigh=768M
MemoryMax=1G
TasksMax=128
EOF

write_managed /etc/systemd/system/redis-server.service.d/10-had-antispam.conf 0644 <<'EOF'
# HAD-ANTISPAM-RSPAMD-MANAGED
[Service]
CPUWeight=30
MemoryHigh=640M
MemoryMax=768M
TasksMax=64
EOF

rspamadm configtest
systemctl daemon-reload
systemctl enable --now redis-server.service
systemctl restart redis-server.service
systemctl enable --now rspamd.service
systemctl restart rspamd.service

redis-cli -h 127.0.0.1 ping | grep -qx PONG || fail 'Redis não respondeu ao ping local.'
READY=0
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 1 http://127.0.0.1:11333/ping 2>/dev/null | grep -qi 'pong'; then READY=1; break; fi
    sleep 0.5
done
[[ "$READY" -eq 1 ]] || fail 'Rspamd normal worker não respondeu no loopback em até 10 segundos.'
systemctl is-active --quiet redis-server.service || fail 'redis-server não ficou ativo.'
systemctl is-active --quiet rspamd.service || fail 'Rspamd não ficou ativo.'

trap - EXIT
printf 'Rspamd %s e Redis ativos; Bayes usa Redis e espera 200 amostras por classe.\n' "$(rspamd --version | head -n1)"
printf 'Scanner/controller vinculados somente a 127.0.0.1; nenhuma porta pública foi aberta.\n'
printf 'Aprendizado automático desativado; classifique apenas exemplos revisados via learn_spam/learn_ham.\n'
printf 'Snapshot de configuração prévia: %s\n' "$BACKUP"
