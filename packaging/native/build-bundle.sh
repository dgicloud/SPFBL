#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo "usage: build-bundle.sh VERSION [SOURCE_ROOT] [OUTPUT_ROOT]" >&2
    exit 2
fi

VERSION=$1
[[ "$VERSION" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid release version" >&2; exit 2; }
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
SOURCE_ROOT=${2:-$(cd -- "$SCRIPT_DIR/../.." && pwd)}
SOURCE_ROOT=$(cd -- "$SOURCE_ROOT" && pwd)
OUTPUT_ROOT=${3:-"$SOURCE_ROOT/dist"}
mkdir -p -- "$OUTPUT_ROOT"
OUTPUT_ROOT=$(cd -- "$OUTPUT_ROOT" && pwd)
PACKAGE="spamfox-${VERSION}"
ARCHIVE="$OUTPUT_ROOT/${PACKAGE}.tar.gz"
[[ ! -e "$ARCHIVE" ]] || { echo "refusing to overwrite $ARCHIVE" >&2; exit 1; }
[[ -f "$SOURCE_ROOT/src/net/spfbl/core/Core.java" ]] || { echo "invalid source root" >&2; exit 1; }

TMP=$(mktemp -d "$OUTPUT_ROOT/.spamfox-build.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT
WORK="$TMP/$PACKAGE"
mkdir -p "$WORK/release/data-seed" "$WORK/native" "$WORK/docs" "$WORK/build"

bash "$SOURCE_ROOT/packaging/native/build-core.sh" "$SOURCE_ROOT" "$WORK/build"
cp -a "$WORK/build/runtime/." "$WORK/release/"
cp -a "$SOURCE_ROOT/data/." "$WORK/release/data-seed/"
cp -a "$SOURCE_ROOT/web" "$WORK/release/web"
cp -a "$SOURCE_ROOT/template" "$WORK/release/template"
cp "$SOURCE_ROOT/licence.txt" "$WORK/release/licence.txt"
mkdir -p "$WORK/release/integrations/common"
cp "$SOURCE_ROOT/integrations/common/spfbl_client.py" "$WORK/release/integrations/common/"
printf '%s\n' "$VERSION" > "$WORK/release/version"

NATIVE_FILES=(
    control.py firewall.py firewall_admin.py backup_restore.py observability.py
    spamfox spamfox-backup spamfox-restore
    spfbl.conf allowed-cpanels.txt spamfox-core.service
    spamfox-firewall.service spamfox-firewall-admin.service spamfox-observability.service
    spamfox-store.service spamfox-store.timer nginx-matrix.conf
    dnsbl-link-override.nft spamfox-firewall-dnsbl-link.conf
)
for name in "${NATIVE_FILES[@]}"; do
    cp "$SOURCE_ROOT/packaging/native/$name" "$WORK/native/$name"
done
cp "$SOURCE_ROOT/packaging/native/install.sh" "$WORK/install.sh"
cp "$SOURCE_ROOT/packaging/native/install-assisted.sh" "$WORK/install-assisted.sh"
cp "$SOURCE_ROOT/packaging/native/README.md" "$WORK/README.md"
cp "$SOURCE_ROOT/docs/BACKUP-RESTORE.md" "$WORK/docs/"
cp "$SOURCE_ROOT/docs/OBSERVABILITY.md" "$WORK/docs/"
cp "$SOURCE_ROOT/docs/CONTENT-BAYES.md" "$WORK/docs/"
cp "$SOURCE_ROOT/docs/FIREWALL.md" "$WORK/docs/"

chmod 0755 "$WORK/install.sh" "$WORK/install-assisted.sh"
for name in control.py firewall.py firewall_admin.py backup_restore.py observability.py spamfox spamfox-backup spamfox-restore; do
    chmod 0755 "$WORK/native/$name"
done
tar -C "$TMP" -czf "$ARCHIVE" "$PACKAGE"
sha256sum "$ARCHIVE"
