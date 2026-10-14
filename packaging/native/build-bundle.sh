#!/usr/bin/env bash
set -euo pipefail

VERSION=${1:?usage: build-bundle.sh VERSION}
[[ "$VERSION" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid release version" >&2; exit 2; }
mkdir -p /output
WORK="/output/had-antispam-${VERSION}"
rm -rf "$WORK"
mkdir -p "$WORK/release/data-seed" "$WORK/native" "$WORK/docs" "$WORK/build"

bash /source/packaging/audit/build-upstream.sh /source "$WORK/build"
cp -a "$WORK/build/runtime/." "$WORK/release/"
cp -a /source/data/. "$WORK/release/data-seed/"
cp -a /source/web "$WORK/release/web"
cp -a /source/template "$WORK/release/template"
cp /source/licence.txt "$WORK/release/licence.txt"
mkdir -p "$WORK/release/integrations/common"
cp /source/integrations/common/{technical_signals.py,spfbl_client.py} "$WORK/release/integrations/common/"
printf '%s\n' "$VERSION" > "$WORK/release/version"

cp /source/packaging/native/{control.py,firewall.py,backup_restore.py,observability.py,had-antispam,had-antispam-backup,had-antispam-restore,spfbl.conf,allowed-cpanels.txt,had-antispam-core.service,had-antispam-firewall.service,had-antispam-observability.service,had-antispam-store.service,had-antispam-store.timer,nginx-matrix.conf,dnsbl-link-override.nft,had-antispam-firewall-dnsbl-link.conf} "$WORK/native/"
cp /source/packaging/native/install.sh "$WORK/install.sh"
cp /source/packaging/native/README.md "$WORK/README.md"
cp /source/docs/{BACKUP-RESTORE.md,OBSERVABILITY.md} "$WORK/docs/"
rm -rf "$WORK/build"
chmod 0755 "$WORK/install.sh" "$WORK/native/control.py" "$WORK/native/firewall.py" "$WORK/native/backup_restore.py" "$WORK/native/observability.py" "$WORK/native/had-antispam" "$WORK/native/had-antispam-backup" "$WORK/native/had-antispam-restore"
tar -C /output -czf "/output/had-antispam-${VERSION}.tar.gz" "had-antispam-${VERSION}"
sha256sum "/output/had-antispam-${VERSION}.tar.gz"
