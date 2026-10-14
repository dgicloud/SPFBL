#!/usr/bin/env bash
set -Eeuo pipefail
cat >&2 <<'EOF'
Este instalador HAD foi descontinuado. Use a WebUI nativa do Rspamd para analisar
um .eml e, somente após revisão humana, enviá-lo como HAM ou SPAM. Nenhuma
alteração foi feita.
EOF
exit 64
