#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Bootstrap pinned to an immutable package checksum.
VERSION='0.2.0-pilot'
PACKAGE="spamfox-content-scan-postfix-${VERSION}"
ARCHIVE="${PACKAGE}.tar.gz"
REPOSITORY='dgicloud/SPFBL'
REF='hadcloud-cpanel-installer'
SHA256='b9c7b76d49c820dd13e08d2dc2ccc12de12b385ff1b5ad7a3038770593e5647b'
BASE_URL="https://raw.githubusercontent.com/${REPOSITORY}/${REF}"
ARCHIVE_URL="${BASE_URL}/packaging/postfix/releases/${ARCHIVE}"
INSTALL_BASE='/opt/spamfox-postfix/releases'
INSTALL_DIR="${INSTALL_BASE}/${PACKAGE}"

usage() {
    cat <<'EOF'
Instalador do monitor de conteúdo SpamFox/Rspamd para Postfix.
O servidor deve estar previamente autorizado por IP na allowlist da VM.

Uso:
  bash spamfox-rspamd.postfix.sh --check
  bash spamfox-rspamd.postfix.sh

Por padrão instala e ativa o filtro after-queue em modo MONITOR.
EOF
}

fail() { printf 'SpamFox Rspamd Postfix: %s\n' "$*" >&2; exit 1; }

if (($# == 1)) && [[ "$1" == '-h' || "$1" == '--help' ]]; then
    usage
    exit 0
fi

MODE=install
if (($# == 1)) && [[ "$1" == '--check' ]]; then
    MODE=check
elif (($#)); then
    fail "argumento desconhecido: $1"
fi

[[ $(id -u) -eq 0 ]] || fail 'execute como root.'
[[ "$SHA256" =~ ^[a-f0-9]{64}$ ]] || fail 'hash do pacote ainda não foi publicado corretamente.'
command -v tar >/dev/null || fail 'tar não encontrado.'
command -v sha256sum >/dev/null || fail 'sha256sum não encontrado.'

if [[ ! -d "$INSTALL_DIR" ]]; then
    command -v curl >/dev/null || command -v wget >/dev/null || fail 'instale curl ou wget para baixar o pacote.'
    install -d -o root -g root -m 0755 "$INSTALL_BASE"
    TEMP_DIR=$(mktemp -d "${INSTALL_BASE}/.${PACKAGE}.XXXXXX")
    cleanup() { rm -rf -- "$TEMP_DIR"; }
    trap cleanup EXIT

    if command -v curl >/dev/null; then
        curl --fail --silent --show-error --location --retry 2 "$ARCHIVE_URL" -o "$TEMP_DIR/$ARCHIVE" || fail 'download do pacote falhou.'
    else
        wget --https-only -q "$ARCHIVE_URL" -O "$TEMP_DIR/$ARCHIVE" || fail 'download do pacote falhou.'
    fi

    printf '%s  %s\n' "$SHA256" "$TEMP_DIR/$ARCHIVE" | sha256sum --check --status || fail 'SHA-256 do pacote não confere.'
    while IFS= read -r ENTRY; do
        [[ "$ENTRY" == "$PACKAGE" || "$ENTRY" == "$PACKAGE/"* ]] || fail 'arquivo inesperado no pacote.'
        [[ "/$ENTRY/" != *'/../'* && "/$ENTRY/" != *'/./'* ]] || fail 'caminho inseguro no pacote.'
    done < <(tar -tzf "$TEMP_DIR/$ARCHIVE")

    tar -xzf "$TEMP_DIR/$ARCHIVE" -C "$TEMP_DIR"
    [[ -r "$TEMP_DIR/$PACKAGE/integrations/postfix/install-content-scan.sh" ]] || fail 'entrypoint ausente no pacote.'
    [[ $(cat "$TEMP_DIR/$PACKAGE/VERSION") == "$VERSION" ]] || fail 'versão interna do pacote divergente.'
    chown -R root:root "$TEMP_DIR/$PACKAGE"
    chmod 0755 "$TEMP_DIR/$PACKAGE" "$TEMP_DIR/$PACKAGE/integrations" "$TEMP_DIR/$PACKAGE/integrations/postfix"
    mv -- "$TEMP_DIR/$PACKAGE" "$INSTALL_DIR"
fi

[[ -f "$INSTALL_DIR/VERSION" && $(cat "$INSTALL_DIR/VERSION") == "$VERSION" ]] || fail "diretório existente não corresponde à versão $VERSION; preservado: $INSTALL_DIR"
[[ -r "$INSTALL_DIR/integrations/postfix/install-content-scan.sh" ]] || fail 'entrypoint do pacote instalado está ausente.'
trap - EXIT
rm -rf -- "${TEMP_DIR:-/nonexistent}"

if [[ "$MODE" == check ]]; then
    exec bash "$INSTALL_DIR/integrations/postfix/validate-content-scan.sh"
fi

bash "$INSTALL_DIR/integrations/postfix/install-content-scan.sh" --reload
bash "$INSTALL_DIR/integrations/postfix/healthcheck-content-scan.sh"
printf 'Monitor SpamFox/Rspamd ativo em MONITOR. O filtro não altera aceitação ou entrega SMTP.\n'
