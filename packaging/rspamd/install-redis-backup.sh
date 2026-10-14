#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fail() { printf 'ERRO: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" == 0 ]] || fail 'Execute como root.'
command -v redis-cli >/dev/null || fail 'redis-cli não está instalado.'
systemctl is-active --quiet redis-server.service || fail 'redis-server.service não está ativo.'
redis-cli --raw PING | grep -qx PONG || fail 'Redis local não respondeu PONG.'

install -d -o root -g root -m 0755 /usr/local/lib/had-content-scan
install -o root -g root -m 0755 "$ROOT/redis_model_backup.py" /usr/local/lib/had-content-scan/redis_model_backup.py
install -o root -g root -m 0755 "$ROOT/had-rspamd-redis-backup" /usr/local/sbin/had-rspamd-redis-backup
install -o root -g root -m 0644 "$ROOT/had-rspamd-redis-backup.service" /etc/systemd/system/had-rspamd-redis-backup.service
install -o root -g root -m 0644 "$ROOT/had-rspamd-redis-backup.timer" /etc/systemd/system/had-rspamd-redis-backup.timer
install -d -o root -g root -m 0700 /var/backups/had-antispam/rspamd/redis
systemd-analyze verify /etc/systemd/system/had-rspamd-redis-backup.service /etc/systemd/system/had-rspamd-redis-backup.timer
systemctl daemon-reload
systemctl enable --now had-rspamd-redis-backup.timer

printf 'Timer instalado sem reiniciar Redis, Rspamd ou SPFBL.\n'
printf 'Crie o primeiro snapshot com: had-rspamd-redis-backup backup\n'
printf 'Verifique um snapshot com: had-rspamd-redis-backup verify /var/backups/had-antispam/rspamd/redis/redis-AAAAMMDDTHHMMSSZ\n'
