#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "$0")" && pwd)
APP=/opt/spfbl
ETC=/etc/spamfox
STATE=/var/lib/spamfox
BACKUP_ROOT=/var/backups/spamfox
LEGACY_DIR=""
LEGACY_WAS_ACTIVE=0
LEGACY_STOPPED=0
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
TEMP_SITE=""
TEMP_SITE_LINK=""
VHOST=""
VHOST_BACKUP=""

fail() { printf 'SpamFox: %s\n' "$*" >&2; exit 1; }
prompt() {
    local label=$1 default=${2-} value
    if [[ -n "$default" ]]; then
        read -r -p "$label [$default]: " value
        printf '%s' "${value:-$default}"
    else
        read -r -p "$label: " value
        printf '%s' "$value"
    fi
}
yesno() {
    local label=$1 default=${2:-y} value hint
    if [[ "$default" == y ]]; then hint='Y/n'; else hint='y/N'; fi
    read -r -p "$label [$hint]: " value
    value=${value:-$default}
    [[ "$value" =~ ^[Yy]$ ]]
}
read_property() {
    local file=$1 key=$2
    [[ -r "$file" ]] || return 0
    sed -n -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*(.*)$/\1/p" "$file" | tail -n 1
}

rollback_legacy() {
    local status=$?
    if (( status != 0 )) && [[ -n "$TEMP_SITE" && -e "$TEMP_SITE" ]]; then
        [[ -z "$TEMP_SITE_LINK" ]] || rm -f -- "$TEMP_SITE_LINK"
        rm -f -- "$TEMP_SITE"
        if command -v nginx >/dev/null 2>&1; then
            nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
        fi
    fi
    if (( status != 0 )) && [[ -n "$VHOST" && -e "$VHOST" ]]; then
        if [[ -n "$VHOST_BACKUP" && -f "$VHOST_BACKUP" ]]; then
            cp -a -- "$VHOST_BACKUP" "$VHOST"
        else
            rm -f -- "$VHOST" /etc/nginx/sites-enabled/spamfox-matrix.conf
        fi
        if command -v nginx >/dev/null 2>&1; then
            nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
        fi
    fi
    if (( status != 0 )) && [[ -n "$LEGACY_DIR" && -d "$LEGACY_DIR" ]]; then
        systemctl disable --now spamfox-core.service spamfox-firewall.service spamfox-firewall-admin.service \
            spamfox-store.timer spamfox-observability.service >/dev/null 2>&1 || true
        if [[ -d "$APP" ]]; then
            mv -- "$APP" "/opt/spfbl.failed.$STAMP" 2>/dev/null || true
        fi
        mv -- "$LEGACY_DIR" "$APP" 2>/dev/null || true
        systemctl daemon-reload >/dev/null 2>&1 || true
        if (( LEGACY_WAS_ACTIVE )); then
            systemctl enable spfbl.service >/dev/null 2>&1 || true
            systemctl start spfbl.service >/dev/null 2>&1 || true
        fi
        printf 'Migração interrompida. A árvore SPFBL anterior foi restaurada; cópia de segurança em %s.\n' \
            "$BACKUP_ROOT" >&2
    fi
    if (( status != 0 && LEGACY_STOPPED && LEGACY_WAS_ACTIVE )) && [[ -z "$LEGACY_DIR" ]]; then
        systemctl enable spfbl.service >/dev/null 2>&1 || true
        systemctl start spfbl.service >/dev/null 2>&1 || true
    fi
    exit "$status"
}

usage() {
    cat <<'EOF'
Uso: install-assisted.sh [--check]

Assistente do pacote nativo SpamFox/SPFBL. Pergunta as opções de instalação,
admin, SMTP, autenticação, allowlist e publicação opcional via Nginx/TLS.
--check valida os arquivos do bundle sem alterar o sistema.
EOF
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
if [[ ${1:-} == --check ]]; then
    [[ -r "$ROOT/release/SPFBL.jar" && -d "$ROOT/release/lib" ]] || fail "bundle sem core Java."
    [[ -x "$ROOT/install.sh" && -r "$ROOT/native/nginx-matrix.conf" ]] || fail "bundle nativo incompleto."
    command -v bash >/dev/null || fail "Bash ausente."
    command -v python3 >/dev/null || fail "Python 3 ausente."
    bash -n "$ROOT/install.sh"
    printf 'PASS: bundle nativo e arquivos do assistente presentes; nenhum arquivo alterado.\n'
    exit 0
fi
[[ $# -eq 0 ]] || { usage >&2; exit 2; }
[[ $(id -u) -eq 0 ]] || fail "execute como root."
[[ -r "$ROOT/release/SPFBL.jar" && -d "$ROOT/release/lib" ]] || fail "bundle sem core Java."
command -v systemctl >/dev/null || fail "systemd não encontrado."
command -v python3 >/dev/null || fail "Python 3 não encontrado."
command -v nft >/dev/null || fail "nftables não encontrado; o firewall não será aberto sem allowlist."
command -v java >/dev/null || fail "Java 11 ou superior não encontrado."

CURRENT_CONFIG="$ETC/spfbl.conf"
if [[ -L "$APP/current" ]]; then
    DETECTED=managed
elif [[ -e "$APP" || -L "$APP" ]]; then
    DETECTED=legacy
else
    DETECTED=fresh
fi
case "$DETECTED" in
    fresh) DEFAULT_MODE=n ;;
    managed) DEFAULT_MODE=u ;;
    legacy) DEFAULT_MODE=m ;;
esac
printf 'Tipo detectado: %s\n' "$DETECTED"
read -r -p "Ação: [n] nova VM, [u] atualizar SpamFox gerenciado, [m] migrar SPFBL legado [$DEFAULT_MODE]: " MODE
MODE=${MODE:-$DEFAULT_MODE}
[[ "$MODE" == n || "$MODE" == u || "$MODE" == m ]] || fail "selecione n, u ou m."
[[ "$MODE" == n && "$DETECTED" == fresh || "$MODE" == u && "$DETECTED" == managed || "$MODE" == m && "$DETECTED" == legacy ]] \
    || fail "a ação escolhida não corresponde à instalação detectada; nada foi alterado."
if [[ "$MODE" == u ]]; then
    yesno "Confirmar atualização do core mantendo dados e configurações atuais?" n || fail "atualização cancelada."
elif [[ "$MODE" == m ]]; then
    printf 'O SPFBL antigo será arquivado, os dados/configuração serão migrados e a cópia antiga ficará preservada.\n'
    read -r -p 'Digite MIGRAR para continuar: ' CONFIRM
    [[ "$CONFIRM" == MIGRAR ]] || fail "migração cancelada."
fi

OLD_HOST=$(read_property "$CURRENT_CONFIG" hostname)
OLD_ADMIN=$(read_property "$CURRENT_CONFIG" admin_email)
DEFAULT_HOST=${OLD_HOST:-matrix.example.com}
HOSTNAME=$(prompt 'Hostname público do painel Matrix/SPFBL' "$DEFAULT_HOST")
ADMIN_EMAIL=$(prompt 'E-mail administrador (define a conta admin do core)' "${OLD_ADMIN:-}")
ADMIN_NAME=$(prompt 'Nome curto do administrador (sem espaços)' 'SpamFoxAdmin')
[[ "$HOSTNAME" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || fail "hostname inválido."
[[ "$ADMIN_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[A-Za-z]{2,63}$ ]] || fail "e-mail administrativo inválido."
[[ "$ADMIN_NAME" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || fail "use um nome curto sem espaços ou símbolos."

EXISTING_ALLOWLIST="$ETC/allowed-cpanels.txt"
[[ -s "$EXISTING_ALLOWLIST" ]] || EXISTING_ALLOWLIST=/etc/had-antispam/allowed-cpanels.txt
ALLOW_TMP=$(mktemp)
trap 'rm -f -- "$ALLOW_TMP"' EXIT
if [[ -s "$EXISTING_ALLOWLIST" ]] && yesno "Manter a allowlist existente em $EXISTING_ALLOWLIST?" y; then
    cp -- "$EXISTING_ALLOWLIST" "$ALLOW_TMP"
else
    printf 'Informe os IPs/CIDRs públicos dos MTAs, um por linha; linha vazia encerra.\n'
    : > "$ALLOW_TMP"
    while true; do
        read -r -p 'IP/CIDR (vazio para terminar): ' CIDR
        [[ -n "$CIDR" ]] || break
        printf '%s\n' "$CIDR" >> "$ALLOW_TMP"
    done
fi
python3 - "$ALLOW_TMP" <<'PY'
import ipaddress, sys
values = []
for number, raw in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    value = raw.split("#", 1)[0].strip()
    if not value:
        continue
    try:
        values.append(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise SystemExit("SpamFox: IP/CIDR inválido na linha %d." % number)
if not values:
    raise SystemExit("SpamFox: informe ao menos um IP/CIDR autorizado.")
PY

CONFIGURE_NGINX=n
PUBLIC_IP=""
LE_EMAIL=""
if [[ "$MODE" == n ]]; then NGINX_DEFAULT=y; else NGINX_DEFAULT=n; fi
if yesno 'Configurar vhost Matrix com Nginx e TLS Let’s Encrypt?' "$NGINX_DEFAULT"; then
    CONFIGURE_NGINX=y
    command -v apt-get >/dev/null || fail "configuração assistida do Nginx/Certbot está disponível somente em Debian/Ubuntu."
    EXISTING_VHOST=/etc/nginx/sites-available/spamfox-matrix.conf
    if [[ -e "$EXISTING_VHOST" ]] && ! grep -q 'Managed by the SpamFox assisted installer' "$EXISTING_VHOST"; then
        fail "$EXISTING_VHOST existe e não pertence ao assistente; vhost preservado."
    fi
    PUBLIC_IP=$(prompt 'IPv4 público da VM' '')
    LE_EMAIL=$(prompt 'E-mail para o certificado TLS' "$ADMIN_EMAIL")
    python3 - "$HOSTNAME" "$PUBLIC_IP" "$LE_EMAIL" <<'PY'
import ipaddress, re, socket, sys
host, public_ip, email = sys.argv[1:]
try:
    address = ipaddress.ip_address(public_ip)
    if address.version != 4:
        raise ValueError()
except ValueError:
    raise SystemExit("SpamFox: informe o IPv4 público da VM.")
if not re.match(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$", email):
    raise SystemExit("SpamFox: e-mail TLS inválido.")
try:
    resolved = {item[4][0] for item in socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)}
except OSError:
    resolved = set()
if public_ip not in resolved:
    raise SystemExit("SpamFox: o DNS A de %s não resolve para %s; corrija o DNS antes do TLS." % (host, public_ip))
PY
    if command -v nginx >/dev/null 2>&1; then
        VHOST_CHECK=$(nginx -T 2>/dev/null | grep -F -m 1 "server_name $HOSTNAME;" || true)
        if [[ -n "$VHOST_CHECK" && ! -f "$EXISTING_VHOST" ]]; then
            fail "Nginx já possui um vhost para $HOSTNAME fora do arquivo SpamFox; preservado, desmarque Nginx ou adapte o vhost existente."
        fi
    fi
fi

TZ_DEFAULT=America/Sao_Paulo
if [[ "$MODE" != n ]] && command -v timedatectl >/dev/null 2>&1; then
    TZ_DEFAULT=$(timedatectl show -p Timezone --value 2>/dev/null || printf 'America/Sao_Paulo')
fi
TIMEZONE=$(prompt 'Fuso horário do sistema' "$TZ_DEFAULT")
[[ -e "/usr/share/zoneinfo/$TIMEZONE" ]] || fail "fuso horário não encontrado: $TIMEZONE."

mkdir -p "$ETC" "$BACKUP_ROOT"
chmod 0750 "$ETC"
install -o root -g root -m 0640 "$ALLOW_TMP" "$ETC/allowed-cpanels.txt"
rm -f -- "$ALLOW_TMP"
trap rollback_legacy EXIT

if [[ "$MODE" == m ]]; then
    BACKUP="$BACKUP_ROOT/spfbl-legacy-$STAMP.tar.gz"
    LEGACY_CONFIG_COPY="$BACKUP_ROOT/spfbl-legacy-config-$STAMP.conf"
    ITEMS=()
    for path in opt/spfbl etc/spfbl etc/spfbl.conf etc/had-antispam etc/spamfox var/lib/had-antispam var/lib/spamfox \
        var/log/spfbl etc/init.d/spfbl etc/systemd/system/spfbl.service etc/cron.d/spfbl etc/logrotate.d/spfbl; do
        [[ -e "/$path" || -L "/$path" ]] && ITEMS+=("$path")
    done
    ((${#ITEMS[@]})) || fail "não encontrei arquivos SPFBL para arquivar."
    if systemctl is-active --quiet spfbl.service; then LEGACY_WAS_ACTIVE=1; fi
    if (( LEGACY_WAS_ACTIVE )); then
        LEGACY_STOPPED=1
        python3 - <<'PY' || true
import socket
try:
    with socket.create_connection(("127.0.0.1", 9875), timeout=2) as sock:
        sock.sendall(b"SHUTDOWN\n")
except OSError:
    pass
PY
        systemctl stop spfbl.service
    fi
    tar -C / -czf "$BACKUP" "${ITEMS[@]}"
    chmod 0600 "$BACKUP"
    for candidate in /etc/spfbl/spfbl.conf /opt/spfbl/spfbl.conf /etc/spfbl.conf; do
        if [[ -f "$candidate" ]]; then cp -p -- "$candidate" "$LEGACY_CONFIG_COPY"; chmod 0600 "$LEGACY_CONFIG_COPY"; break; fi
    done
    if [[ -d /opt/spfbl/data ]]; then
        if [[ -d "$STATE/data" ]] && find "$STATE/data" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
            [[ $(realpath -m /opt/spfbl/data) == $(realpath -m "$STATE/data") ]] \
                || fail "há dados distintos em /opt/spfbl/data e $STATE/data; backup criado em $BACKUP, mas a migração foi interrompida para evitar mesclagem ambígua."
        else
            mkdir -p "$STATE/data"
            cp -a /opt/spfbl/data/. "$STATE/data/"
        fi
    fi
    if [[ -d /opt/spfbl/history ]]; then
        if [[ -d "$STATE/history" ]] && find "$STATE/history" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
            [[ $(realpath -m /opt/spfbl/history) == $(realpath -m "$STATE/history") ]] \
                || fail "há históricos distintos em /opt/spfbl/history e $STATE/history; backup criado em $BACKUP, mas a migração foi interrompida."
        else
            mkdir -p "$STATE/history"
            cp -a /opt/spfbl/history/. "$STATE/history/"
        fi
    fi
    systemctl disable spfbl.service >/dev/null 2>&1 || true
    LEGACY_DIR="/opt/spfbl.legacy.$STAMP"
    mv -- /opt/spfbl "$LEGACY_DIR"
    printf 'Backup SPFBL legado: %s\n' "$BACKUP"
    [[ ! -e "$LEGACY_CONFIG_COPY" ]] || printf 'Configuração antiga preservada: %s\n' "$LEGACY_CONFIG_COPY"
fi

if [[ "$MODE" == m && -n "${LEGACY_CONFIG_COPY:-}" && -f "$LEGACY_CONFIG_COPY" \
    && ! -f "$ETC/spfbl.conf" && ! -f /etc/had-antispam/spfbl.conf ]]; then
    LEGACY_CONFIG_PENDING=1
fi

if command -v timedatectl >/dev/null 2>&1; then
    timedatectl set-timezone "$TIMEZONE"
fi
bash "$ROOT/install.sh"
if [[ "${LEGACY_CONFIG_PENDING:-0}" == 1 ]]; then
    install -o root -g spamfox -m 0640 "$LEGACY_CONFIG_COPY" "$ETC/spfbl.conf"
fi

python3 - "$HOSTNAME" "$ADMIN_EMAIL" "$ADMIN_NAME" "$TIMEZONE" "$MODE" <<'PY'
import getpass
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

config_path = "/etc/spamfox/spfbl.conf"
hostname, admin_email, admin_name, timezone, mode = sys.argv[1:]
email_re = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")

def ask(label, default=None):
    prompt = label + (" [%s]" % default if default is not None else "") + ": "
    value = input(prompt).strip()
    return value if value else (default or "")

def yes(label, default):
    raw = ask(label + (" (S/n)" if default else " (s/N)"), "s" if default else "n").lower()
    return raw in ("s", "sim", "y", "yes")

def escape_property(value):
    result = []
    for index, char in enumerate(value):
        code = ord(char)
        if char in "\\\t\n\r\f" or char in "=:#!" or (index == 0 and char == " "):
            result.append("\\" + {"\t": "t", "\n": "n", "\r": "r", "\f": "f"}.get(char, char))
        elif code > 255:
            result.append("\\u%04x" % code)
        else:
            result.append(char)
    return "".join(result)

def atomic_config(text):
    descriptor, temporary = tempfile.mkstemp(prefix=".spfbl.conf.", dir=os.path.dirname(config_path))
    try:
        with os.fdopen(descriptor, "w", encoding="latin-1") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, 0, __import__("grp").getgrnam("spamfox").gr_gid)
        os.chmod(temporary, 0o640)
        os.replace(temporary, config_path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise

with open(config_path, "r", encoding="latin-1") as stream:
    old_text = stream.read()
old_lines = old_text.splitlines()
current = {}
for line in old_lines:
    match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*[=:]\s*(.*)$", line)
    if match:
        current[match.group(1)] = match.group(2)

configure_smtp_default = mode == "n" and not current.get("smtp_host")
smtp_keys = set()
if yes("Configurar/alterar SMTP de saída agora?", configure_smtp_default):
    smtp_host = ask("Host SMTP", current.get("smtp_host", ""))
    if not re.match(r"^[A-Za-z0-9.-]+$", smtp_host):
        raise SystemExit("SpamFox: hostname SMTP inválido.")
    smtp_port = ask("Porta SMTP (STARTTLS; normalmente 587, 25 ou 2525)", current.get("smtp_port", "587"))
    if not smtp_port.isdigit() or not 1 <= int(smtp_port) <= 65535 or int(smtp_port) == 465:
        raise SystemExit("SpamFox: porta SMTP inválida; o core usa SMTP/STARTTLS e não SMTPS implícito na porta 465.")
    smtp_starttls = yes("Ativar STARTTLS?", True)
    smtp_auth = yes("O relay exige autenticação?", True)
    smtp_user = ""
    smtp_password = ""
    if smtp_auth:
        smtp_user = ask("Usuário SMTP")
        smtp_password = getpass.getpass("Senha SMTP (não será exibida): ")
        if not smtp_user or not smtp_password:
            raise SystemExit("SpamFox: usuário e senha SMTP são obrigatórios com autenticação.")
    current.update({
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_starttls": str(smtp_starttls).lower(),
        "smtp_auth": str(smtp_auth).lower(),
        "smtp_user": smtp_user,
        "smtp_password": smtp_password,
    })
    smtp_keys = {"smtp_auth", "smtp_starttls", "smtp_host", "smtp_port", "smtp_user", "smtp_password"}
else:
    current.setdefault("smtp_host", "")

if not email_re.match(admin_email):
    raise SystemExit("SpamFox: e-mail admin inválido.")
current["hostname"] = hostname
current["admin_email"] = admin_email

original = old_text
keys = {"hostname", "admin_email"} | smtp_keys
new_lines = []
seen = set()
for line in old_lines:
    match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*[=:]", line)
    if match and match.group(1) in keys:
        key = match.group(1)
        if key not in seen:
            new_lines.append(key + "=" + escape_property(current.get(key, "")))
            seen.add(key)
    else:
        new_lines.append(line)
for key in sorted(keys - seen):
    new_lines.append(key + "=" + escape_property(current.get(key, "")))
new_text = "\n".join(new_lines) + "\n"
atomic_config(new_text)

result = subprocess.run(["systemctl", "restart", "spamfox-core.service"])
if result.returncode:
    atomic_config(original)
    subprocess.run(["systemctl", "restart", "spamfox-core.service"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    raise SystemExit("SpamFox: core não reiniciou após salvar a configuração; confira systemctl status spamfox-core.")
ready = False
for _ in range(300):
    try:
        with socket.create_connection(("127.0.0.1", 9875), timeout=2) as connection:
            connection.settimeout(3)
            connection.sendall(b"VERSION\n")
            response = connection.recv(256).decode("ascii", "replace").strip()
            if response.startswith("SPFBL-"):
                ready = True
                break
    except OSError:
        pass
    time.sleep(2)
if not ready:
    raise SystemExit("SpamFox: core não respondeu VERSION em até 600 segundos.")

def admin(command):
    with socket.create_connection(("127.0.0.1", 9875), timeout=3) as connection:
        connection.settimeout(5)
        connection.sendall((command + "\n").encode("utf-8"))
        response = bytearray()
        while len(response) < 4096:
            chunk = connection.recv(512)
            if not chunk:
                break
            response.extend(chunk)
            if b"\n" in chunk:
                break
    return bytes(response).decode("utf-8", "replace").splitlines()[0].strip()

user_response = admin("USER ADD %s %s" % (admin_email, admin_name))
if not (user_response.startswith("ADDED ") or user_response == "ALREADY EXISTS"):
    raise SystemExit("SpamFox: não foi possível criar/encontrar o usuário admin (resposta: %s)." % user_response[:120])
print("Conta admin do core: %s" % ("criada" if user_response.startswith("ADDED ") else "já existente"))

if mode == "n":
    auth_default = "2" if current.get("smtp_host") else "1"
else:
    auth_default = "3"
print("Autenticação web do admin: 1=TOTP por e-mail, 2=senha estática, 3=preservar credencial atual")
auth_mode = ask("Escolha", auth_default)
if auth_mode == "1":
    if not current.get("smtp_host"):
        raise SystemExit("SpamFox: TOTP requer SMTP configurado. Configure SMTP e execute novamente.")
    totp_response = admin("USER SEND %s TOTP" % admin_email)
    if not totp_response.startswith("TOTP SENT TO "):
        raise SystemExit("SpamFox: o core não confirmou envio do TOTP (%s). Verifique SMTP e os logs." % totp_response[:100])
    print("TOTP enviado para %s." % admin_email)
    auth_summary = "TOTP enviado"
elif auth_mode == "2":
    password_re = re.compile(r"^[0-9a-zA-Z@#$%%!&?;<>{}]{8,32}$")
    while True:
        password = getpass.getpass("Nova senha estática do admin (8-32 caracteres permitidos pelo core): ")
        confirm = getpass.getpass("Confirme a senha: ")
        if password != confirm:
            print("As senhas não coincidem; tente novamente.")
            continue
        if not password_re.match(password):
            print("Senha fora do formato aceito pelo core SPFBL.")
            continue
        response = admin("USER SET %s PASSWORD %s" % (admin_email, password))
        password = confirm = ""
        if response.startswith("CHANGED TO ") or response == "NOT CHANGED":
            print("Senha estática configurada; o segredo não foi exibido nem registrado pelo assistente.")
            auth_summary = "senha estática pronta"
            break
        raise SystemExit("SpamFox: core não aceitou a senha estática (%s)." % response[:100])
elif auth_mode == "3":
    print("Credencial atual preservada.")
    auth_summary = "credencial preservada"
else:
    raise SystemExit("SpamFox: escolha 1, 2 ou 3.")
print("Core: versão e conta admin confirmadas; autenticação: %s." % auth_summary)
PY

if [[ "$CONFIGURE_NGINX" == y ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y nginx certbot
    SITE_DIR=/etc/nginx/sites-available
    ENABLED_DIR=/etc/nginx/sites-enabled
    install -d -m 0755 /var/www/letsencrypt "$SITE_DIR" "$ENABLED_DIR"
    TEMP_SITE_CANDIDATE="$SITE_DIR/spamfox-matrix-acme.conf"
    if [[ -e "$TEMP_SITE_CANDIDATE" ]] && ! grep -q 'Managed temporary ACME vhost for SpamFox' "$TEMP_SITE_CANDIDATE"; then
        fail "$TEMP_SITE_CANDIDATE existe e não pertence ao assistente; arquivo preservado."
    fi
    TEMP_SITE_LINK="$ENABLED_DIR/spamfox-matrix-acme.conf"
    if [[ ( -e "$TEMP_SITE_LINK" || -L "$TEMP_SITE_LINK" ) && ! -L "$TEMP_SITE_LINK" ]]; then
        fail "$TEMP_SITE_LINK existe e não é um link do assistente; arquivo preservado."
    fi
    if [[ -L "$TEMP_SITE_LINK" && $(readlink -- "$TEMP_SITE_LINK") != "$TEMP_SITE_CANDIDATE" ]]; then
        fail "$TEMP_SITE_LINK aponta para um vhost diferente; arquivo preservado."
    fi
    TEMP_SITE="$TEMP_SITE_CANDIDATE"
    cat > "$TEMP_SITE" <<EOF
# Managed temporary ACME vhost for SpamFox
server {
    listen 80;
    listen [::]:80;
    server_name $HOSTNAME;
    location ^~ /.well-known/acme-challenge/ { root /var/www/letsencrypt; default_type text/plain; try_files \$uri =404; }
    location / { return 404; }
}
EOF
    ln -sfn "$TEMP_SITE" "$TEMP_SITE_LINK"
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
    certbot certonly --webroot -w /var/www/letsencrypt -d "$HOSTNAME" \
        --email "$LE_EMAIL" --agree-tos --non-interactive --keep-until-expiring
    rm -f -- "$TEMP_SITE_LINK"
    TEMP_SITE_LINK=""
    VHOST_CANDIDATE="$SITE_DIR/spamfox-matrix.conf"
    if [[ ( -e "$VHOST_CANDIDATE" || -L "$VHOST_CANDIDATE" ) ]] && ! grep -q 'Managed by the SpamFox assisted installer' "$VHOST_CANDIDATE"; then
        fail "$VHOST_CANDIDATE existe e não pertence ao assistente; preservei o vhost existente."
    fi
    VHOST="$VHOST_CANDIDATE"
    if [[ -e "$VHOST" ]]; then
        VHOST_BACKUP="$BACKUP_ROOT/spamfox-matrix-$STAMP.conf"
        cp -a "$VHOST" "$VHOST_BACKUP"
    fi
    python3 - "$ROOT/native/nginx-matrix.conf" "$VHOST" "$HOSTNAME" <<'PY'
import os, sys, tempfile
source, target, hostname = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    content = stream.read().replace("matrix.example.com", hostname)
fd, temporary = tempfile.mkstemp(prefix=".spamfox-matrix.", dir=os.path.dirname(target), text=True)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    stream.write(content)
    stream.flush()
    os.fsync(stream.fileno())
os.chmod(temporary, 0o644)
os.replace(temporary, target)
PY
    ln -sfn "$VHOST" "$ENABLED_DIR/spamfox-matrix.conf"
    rm -f -- "$TEMP_SITE"
    if ! nginx -t; then
        [[ ! -e "$BACKUP_ROOT/spamfox-matrix-$STAMP.conf" ]] || cp -a "$BACKUP_ROOT/spamfox-matrix-$STAMP.conf" "$VHOST"
        fail "nginx -t falhou; vhost anterior restaurado quando havia backup."
    fi
    systemctl reload nginx
    TEMP_SITE=""
fi

INSTALL_SUCCEEDED=1
trap - EXIT
printf '\nSpamFox está instalado/atualizado.\n'
printf 'Core e consulta: TCP 9877, limitado pela allowlist /etc/spamfox/allowed-cpanels.txt.\n'
printf 'Painel: %s\n' "$(if [[ "$CONFIGURE_NGINX" == y ]]; then printf 'https://%s/pt/' "$HOSTNAME"; else printf 'vhost Nginx não configurado'; fi)"
printf 'ADMIN 9875 e HTTP 8080 permanecem privados. Estado persistente: %s.\n' "$STATE"
printf 'Status: spamfox status; backup/restore: spamfox-backup e spamfox-restore.\n'
