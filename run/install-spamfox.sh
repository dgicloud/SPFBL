#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPOSITORY='dgicloud/SPFBL'
BRANCH='spamfox'
VERSION=$(date -u +%Y%m%d%H%M%S)
PACKAGE="spamfox-${VERSION}"
fail() { printf 'SpamFox bootstrap: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Uso: bash install-spamfox.sh [--check]

Baixa a branch SpamFox, compila o core SPFBL nativo, gera o pacote e inicia
o assistente de instalação/upgrade. Compatível com Debian e Ubuntu.
EOF
}
if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
[[ $# -eq 0 || ${1:-} == --check ]] || { usage >&2; exit 2; }
CHECK_ONLY=0
[[ ${1:-} != --check ]] || CHECK_ONLY=1
[[ $(id -u) -eq 0 ]] || fail 'execute como root.'
WORK=$(mktemp -d /root/spamfox-install.XXXXXX)
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT
command -v apt-get >/dev/null || fail 'esta versão automatiza dependências em Debian/Ubuntu.'
command -v curl >/dev/null || fail 'curl é necessário.'
command -v tar >/dev/null || fail 'tar é necessário.'

curl -fsSL --retry 3 "https://codeload.github.com/${REPOSITORY}/tar.gz/refs/heads/${BRANCH}" \
    -o "$WORK/source.tar.gz"
mkdir -p "$WORK/source"
tar -xzf "$WORK/source.tar.gz" -C "$WORK/source" --strip-components=1

if (( CHECK_ONLY )); then
    bash -n "$WORK/source/packaging/native/build-bundle.sh"
    bash -n "$WORK/source/packaging/native/install-assisted.sh"
    printf 'PASS: branch %s baixada; pré-checagem local terminou sem instalar o core.\n' "$BRANCH"
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl nftables openjdk-17-jdk-headless python3 tar

bash "$WORK/source/packaging/native/build-bundle.sh" "$VERSION" "$WORK/source" "$WORK/out"
tar -xzf "$WORK/out/${PACKAGE}.tar.gz" -C "$WORK"
bash "$WORK/$PACKAGE/install-assisted.sh"
