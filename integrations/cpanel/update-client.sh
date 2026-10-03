#!/usr/bin/env bash
set -Eeuo pipefail
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
[[ $(id -u) -eq 0 ]] || { echo "Execute como root." >&2; exit 1; }
[[ -e /etc/systemd/system/had-antispam-client.service ]] || { echo "Cliente HAD direto não está instalado." >&2; exit 1; }
SERVER=${HAD_SPFBL_HOST:-$(sed -n 's/^HAD_SPFBL_HOST=//p' /etc/had-antispam/client.conf)}
PORT=${HAD_SPFBL_PORT:-$(sed -n 's/^HAD_SPFBL_PORT=//p' /etc/had-antispam/client.conf)}
[[ -n "$SERVER" && -n "$PORT" ]] || { echo "Endpoint HAD ausente." >&2; exit 1; }
python3 - "$SERVER" "$PORT" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
with socket.create_connection((host, port), timeout=2.0) as connection:
    connection.settimeout(2.0)
    connection.sendall(b"VERSION\n")
    response = connection.recv(256).decode("iso-8859-1", "replace")
if not response.startswith("SPFBL-"):
    raise SystemExit("HAD core respondeu de forma inesperada: " + response[:100])
PY
install -o root -g root -m 0644 "$HERE/had_antispam_client.py" /usr/local/libexec/had-antispam/had_antispam_client.py
install -o root -g root -m 0644 "$HERE/../common/spfbl_client.py" /usr/local/libexec/had-antispam/spfbl_client.py
install -o root -g root -m 0644 "$HERE/had-antispam-client.service" /etc/systemd/system/had-antispam-client.service
systemctl daemon-reload
systemctl restart had-antispam-client.service
systemctl is-active --quiet had-antispam-client.service
echo "Cliente HAD atualizado em MONITOR/fail-open; destino ${SERVER}:${PORT}."
