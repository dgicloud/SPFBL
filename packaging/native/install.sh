#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "$0")" && pwd)
VERSION=$(cat "$ROOT/release/version")
APP=/opt/spfbl
RELEASES="$APP/releases"
NEW_RELEASE="$RELEASES/$VERSION"
ETC=/etc/had-antispam
STATE=/var/lib/had-antispam
LOGS=/var/log/had-antispam
LIBEXEC=/usr/local/lib/had-antispam
SBIN=/usr/local/sbin
OLD_RELEASE=""

fail() { echo "HAD AntiSpam install: $*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || fail "execute como root."
command -v systemctl >/dev/null || fail "systemd não encontrado."
command -v nft >/dev/null || fail "nftables não encontrado; o listener não será aberto sem allowlist."
command -v python3 >/dev/null || fail "Python 3 não encontrado."
[[ -r "$ROOT/release/SPFBL.jar" && -d "$ROOT/release/lib" ]] || fail "bundle inválido ou incompleto."

JAVA_VERSION=$(java -version 2>&1 | sed -n '1s/.*version "\([0-9]*\).*/\1/p')
[[ "$JAVA_VERSION" =~ ^[0-9]+$ ]] || fail "Java não encontrado ou versão não identificada."
(( JAVA_VERSION >= 11 )) || fail "Java 11 ou superior é necessário."

if ! getent group hadantispam >/dev/null; then groupadd --system hadantispam; fi
if ! id hadantispam >/dev/null 2>&1; then
    useradd --system --gid hadantispam --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin hadantispam
fi
install -d -o root -g root -m 0755 "$APP" "$RELEASES"
install -d -o root -g hadantispam -m 0750 "$ETC"
chown root:hadantispam "$ETC"
chmod 0750 "$ETC"
install -d -o hadantispam -g hadantispam -m 0750 "$STATE" "$STATE/data" "$STATE/history" "$LOGS"
install -d -o root -g root -m 0755 "$LIBEXEC" "$SBIN"

if [[ ! -e "$STATE/data" || -z "$(find "$STATE/data" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    cp -a "$ROOT/release/data-seed/." "$STATE/data/"
fi
if [[ ! -e "$STATE/history" ]]; then install -d -o hadantispam -g hadantispam -m 0750 "$STATE/history"; fi
chown -R hadantispam:hadantispam "$STATE/data" "$STATE/history"

if [[ ! -e "$ETC/spfbl.conf" ]]; then install -o root -g hadantispam -m 0640 "$ROOT/native/spfbl.conf" "$ETC/spfbl.conf"; fi
chown root:hadantispam "$ETC/spfbl.conf"
chmod 0640 "$ETC/spfbl.conf"
if [[ ! -e "$ETC/allowed-cpanels.txt" ]]; then install -o root -g root -m 0640 "$ROOT/native/allowed-cpanels.txt" "$ETC/allowed-cpanels.txt"; fi
[[ -s "$ETC/allowed-cpanels.txt" ]] || fail "allowlist vazia; nenhum cPanel será exposto."

if [[ -e "$NEW_RELEASE" ]]; then fail "release $VERSION já existe; escolha outra versão. sem sobrescrever arquivos instalados."; fi
install -d -o root -g root -m 0755 "$NEW_RELEASE"
cp -a "$ROOT/release/." "$NEW_RELEASE/"
install -o root -g root -m 0755 "$ROOT/native/control.py" "$NEW_RELEASE/control.py"
install -o root -g root -m 0755 "$ROOT/native/firewall.py" "$NEW_RELEASE/firewall.py"
install -o root -g root -m 0755 "$ROOT/native/observability.py" "$NEW_RELEASE/observability.py"
install -o root -g root -m 0755 "$ROOT/native/control.py" "$LIBEXEC/control.py"
install -o root -g root -m 0755 "$ROOT/native/backup_restore.py" "$LIBEXEC/backup_restore.py"
install -o root -g root -m 0755 "$ROOT/native/had-antispam-backup" "$SBIN/had-antispam-backup"
install -o root -g root -m 0755 "$ROOT/native/had-antispam-restore" "$SBIN/had-antispam-restore"
install -o root -g root -m 0755 "$ROOT/native/had-antispam" "$NEW_RELEASE/had-antispam"
chown -R root:root "$NEW_RELEASE"
chmod -R go-w "$NEW_RELEASE"

if [[ -L "$APP/current" ]]; then OLD_RELEASE=$(readlink -f "$APP/current");
elif [[ -e "$APP/current" ]]; then fail "$APP/current existe e não é um link simbólico; instalação cancelada."; fi

rollback() {
    local status=$?
    if (( status != 0 )); then
        systemctl stop had-antispam-core.service >/dev/null 2>&1 || true
        if [[ -n "$OLD_RELEASE" && -d "$OLD_RELEASE" ]]; then
            ln -sfn "$OLD_RELEASE" "$APP/current"
            systemctl daemon-reload
            systemctl start had-antispam-core.service >/dev/null 2>&1 || true
            if [[ -r "$OLD_RELEASE/observability.py" ]]; then
                systemctl enable had-antispam-observability.service >/dev/null 2>&1 || true
                systemctl restart had-antispam-observability.service >/dev/null 2>&1 || true
            else
                systemctl disable had-antispam-observability.service >/dev/null 2>&1 || true
                systemctl stop had-antispam-observability.service >/dev/null 2>&1 || true
            fi
        else
            systemctl disable had-antispam-observability.service >/dev/null 2>&1 || true
            systemctl stop had-antispam-observability.service >/dev/null 2>&1 || true
        fi
        echo "Instalação falhou; a release anterior foi restaurada quando existia. Docker e dados existentes foram preservados." >&2
    fi
    exit "$status"
}
trap rollback EXIT

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
link_path "$SBIN/had-antispam" "$APP/current/had-antispam"

install -o root -g root -m 0644 "$ROOT/native/had-antispam-core.service" /etc/systemd/system/had-antispam-core.service
install -o root -g root -m 0644 "$ROOT/native/had-antispam-firewall.service" /etc/systemd/system/had-antispam-firewall.service
install -o root -g root -m 0644 "$ROOT/native/had-antispam-observability.service" /etc/systemd/system/had-antispam-observability.service
install -o root -g root -m 0644 "$ROOT/native/had-antispam-store.service" /etc/systemd/system/had-antispam-store.service
install -o root -g root -m 0644 "$ROOT/native/had-antispam-store.timer" /etc/systemd/system/had-antispam-store.timer
systemctl daemon-reload
systemctl enable had-antispam-firewall.service had-antispam-core.service had-antispam-store.timer had-antispam-observability.service >/dev/null
systemctl start had-antispam-firewall.service
systemctl restart had-antispam-core.service
READY=0
for attempt in $(seq 1 60); do
    if systemctl is-active --quiet had-antispam-core.service \
        && "$APP/current/control.py" version >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 2
done
[[ "$READY" -eq 1 ]] || fail "serviço nativo não respondeu VERSION em até 120 segundos."
systemctl start had-antispam-store.timer
systemctl restart had-antispam-observability.service
OBSERVABILITY_READY=0
for attempt in $(seq 1 15); do
    if python3 -c 'from urllib.request import urlopen; r=urlopen("http://127.0.0.1:9911/health", timeout=2); assert r.status == 200; assert b"\"status\": \"ok\"" in r.read(); r=urlopen("http://127.0.0.1:9911/metrics", timeout=2); assert b"had_antispam_core_up 1" in r.read()' >/dev/null 2>&1; then
        OBSERVABILITY_READY=1
        break
    fi
    sleep 1
done
[[ "$OBSERVABILITY_READY" -eq 1 ]] || fail "serviço de observabilidade não respondeu /health e /metrics em até 15 segundos."
trap - EXIT
echo "HAD AntiSpam $VERSION ativo. Consulta TCP 9877 protegida por /etc/had-antispam/allowed-cpanels.txt; firewall bloqueia ADMIN 9875 e HTTP 8080 externamente."
echo "Para adicionar cPanels, inclua cada IP/CIDR de saída na allowlist e execute: systemctl restart had-antispam-firewall.service"
echo "Backup: had-antispam-backup. Restore versionado: had-antispam-restore /var/backups/had-antispam/ARQUIVO.tar.gz --dry-run; aplique com --yes."
echo "Status: had-antispam status."
