# SpamFox no Postfix

O cliente conecta o Postfix ao core SPFBL por meio de `check_policy_service`. O perfil publicado permanece em MONITOR: registra o resultado da consulta, responde `DUNNO` e não altera o aceite SMTP.

Cadastre o IP/CIDR público do Postfix como `CLIENT` no core e na allowlist de TCP 9877 antes de instalar.

```bash
curl -fsSLO https://raw.githubusercontent.com/dgicloud/SPFBL/spamfox/client/spamfox.postfix.sh
bash spamfox.postfix.sh --check
bash spamfox.postfix.sh
```

O instalador cria snapshot, valida `postfix check`, executa o smoke de protocolo e recarrega o serviço somente após validação. O cliente de envelope não envia corpo ou arquivo `.eml`. O atualizador também remove o transporte legado de envio de mensagens completas quando `content_filter` está vazio e a fila do Postfix está vazia; se houver mensagens pendentes ou filtro ativo, ele para e preserva a configuração. A limpeza não altera milters locais. O treinamento do Bayes nativo é feito pelo upload rotulado no painel web do SPFBL.

```bash
postfix check
systemctl is-active postfix
postconf -n | grep check_policy_service
```
