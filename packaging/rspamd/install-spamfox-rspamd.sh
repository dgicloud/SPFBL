#!/usr/bin/env bash
set -Eeuo pipefail

cat >&2 <<'EOF'
Instalador legado desativado: SpamFox agora usa o Bayes nativo do core SPFBL.
Este comando não instala nem habilita Rspamd ou Redis.

Gateway after-queue: ../../integrations/content_scan/README.md
Treino de EML no painel nativo: ../../docs/CONTENT-BAYES.md
EOF
exit 64
