#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Bootstrap pinned to an immutable package checksum. Update the version and
# digest only after building and reviewing a new cPanel release bundle.
VERSION='0.1.11-pilot'
PACKAGE="spamfox-rspamd-cpanel-${VERSION}"
ARCHIVE="${PACKAGE}.tar.gz"
REPOSITORY='dgicloud/SPFBL'
REF='hadcloud-cpanel-installer'
SHA256='12197017c2e0993d4087ae779e1b8e89231f00b30d96b684c4052bd3968e29e9'
BASE_URL="https://raw.githubusercontent.com/${REPOSITORY}/${REF}"
ARCHIVE_URL="${BASE_URL}/packaging/cpanel/releases/${ARCHIVE}"
INSTALL_BASE='/opt/spamfox-cpanel/releases'
INSTALL_DIR="${INSTALL_BASE}/${PACKAGE}"

usage() {
    cat <<'EOF'
Instalador do coletor de conteúdo Rspamd para cPanel/Exim.
Este add-on mantém o cliente nativo SPFBL e instala somente a cópia after-queue.

Uso:
  bash spamfox-rspamd.cpanel.sh --client-id ID --test-recipient CAIXA --check
  bash spamfox-rspamd.cpanel.sh --client-id ID --test-recipient CAIXA --token-file ARQUIVO

O token individual é emitido na VM central e deve estar em arquivo root-only.
Configure antes o transporte had_sfox_content_pipe no WHM; consulte o guia do pacote.
EOF
}

fail() { printf 'SpamFox Rspamd cPanel: %s\n' "$*" >&2; exit 1; }

if (($# == 1)) && [[ "$1" == '-h' || "$1" == '--help' ]]; then
    usage
    exit 0
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
    [[ -r "$TEMP_DIR/$PACKAGE/integrations/cpanel/spamfox-rspamd.cpanel.sh" ]] || fail 'entrypoint ausente no pacote.'
    [[ $(cat "$TEMP_DIR/$PACKAGE/VERSION") == "$VERSION" ]] || fail 'versão interna do pacote divergente.'
    chown -R root:root "$TEMP_DIR/$PACKAGE"
    chmod 0755 "$TEMP_DIR/$PACKAGE" "$TEMP_DIR/$PACKAGE/integrations" "$TEMP_DIR/$PACKAGE/integrations/cpanel"
    mv -- "$TEMP_DIR/$PACKAGE" "$INSTALL_DIR"
fi

[[ -f "$INSTALL_DIR/VERSION" && $(cat "$INSTALL_DIR/VERSION") == "$VERSION" ]] || fail "diretório existente não corresponde à versão $VERSION; preservado: $INSTALL_DIR"
[[ -r "$INSTALL_DIR/integrations/cpanel/spamfox-rspamd.cpanel.sh" ]] || fail 'entrypoint do pacote instalado está ausente.'
trap - EXIT
rm -rf -- "${TEMP_DIR:-/nonexistent}"
exec bash "$INSTALL_DIR/integrations/cpanel/spamfox-rspamd.cpanel.sh" "$@"
