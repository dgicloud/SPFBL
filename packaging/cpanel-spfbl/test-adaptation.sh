#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
installer="$script_dir/spfbl.cpanel.sh"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

awk '
    /^# HADCloud adaptation:/ { capture = 1 }
    /^function exim_configuration\(\)/ { capture = 0 }
    capture { print }
' "$installer" > "$tmp_dir/helpers.sh"
source "$tmp_dir/helpers.sh"

client="$tmp_dir/spfbl"
printf '%s\n' 'IP_SERVIDOR="54.233.253.229"' 'PORTA_SERVIDOR="9877"' > "$client"
configure_query_server_client "$client"
grep -Fqx 'IP_SERVIDOR="151.242.41.35"' "$client"

firewall="$tmp_dir/firewall-update"
printf '%s\n' 'echo "FIREWALL" | nc -w 60 54.233.253.229 9877 > /tmp/spfbl-firewall' > "$firewall"
configure_query_server_firewall "$firewall"
grep -Fq 'nc -w 60 151.242.41.35 9877' "$firewall"

ambiguous_client="$tmp_dir/ambiguous-client"
printf '%s\n' 'IP_SERVIDOR="54.233.253.229"' 'IP_SERVIDOR="54.233.253.229"' > "$ambiguous_client"
if configure_query_server_client "$ambiguous_client"; then
    echo "Expected duplicated client setting to fail closed" >&2
    exit 1
fi
grep -Fqx 'IP_SERVIDOR="54.233.253.229"' "$ambiguous_client"

ambiguous_firewall="$tmp_dir/ambiguous-firewall"
printf '%s\n' '54.233.253.229 9877' '54.233.253.229 9875' > "$ambiguous_firewall"
if configure_query_server_firewall "$ambiguous_firewall"; then
    echo "Expected duplicated firewall endpoint to fail closed" >&2
    exit 1
fi
grep -Fq '54.233.253.229' "$ambiguous_firewall"

test "$(grep -F -c 'configure_query_server_client /usr/local/bin/spfbl || exit 1' "$installer")" -eq 2
test "$(grep -F -c 'spamd_address = 151.242.41.35 9877 retry=30s tmo=3m' "$installer")" -eq 3

echo "PASS: endpoint patching, fail-closed checks, and installer/update integration"
