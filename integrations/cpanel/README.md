# SpamFox no cPanel/Exim

O cliente mantém o protocolo e o core SPFBL. Ele instala o cliente de consulta de envelope e, quando habilitada, usa ACLs persistentes do cPanel para sobreviver ao rebuild do Exim.

Antes da instalação, cadastre o IP público de saída do servidor como `CLIENT` no core e na allowlist de TCP 9877. A VM central deve responder `VERSION` ao host.

```bash
curl -fsSLO https://raw.githubusercontent.com/dgicloud/SPFBL/spamfox/client/spamfox.cpanel.sh
bash spamfox.cpanel.sh install
```

O instalador salva estado para atualização e rollback, valida o core e reconstrói o Exim pelas ferramentas do cPanel. Para validar a configuração antes de aplicar, use o instalador assistido `integrations/cpanel/install-exim-cpanel.sh` com `--check` e um destinatário local existente.

As ACLs RCPT consultam o envelope SPFBL. A ACL DATA/HEADER opcional envia somente cabeçalhos e metadados ao core para o painel e feedback nativo; ela não envia corpo nem arquivo `.eml`. O Bayes é treinado pelo upload rotulado no painel web.

Use os subcomandos `update`, `uninstall` e `firewall` do cliente conforme a ajuda do script. Não altere `/etc/exim.conf` diretamente: o cPanel o reconstrói.
