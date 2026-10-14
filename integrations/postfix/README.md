# SpamFox no Postfix

A integração SPFBL de envelope é suportada e roda em MONITOR: o policy daemon devolve `DUNNO`, portanto não altera a decisão de entrega do Postfix. O core consultado é `203.0.113.10:9877`.

## Cliente SPFBL

Cadastre e libere o IP público do Postfix na VM central antes da instalação.

```bash
curl -fsSLO https://raw.githubusercontent.com/dgicloud/SPFBL/hadcloud-cpanel-installer/client/spamfox.postfix.sh
bash spamfox.postfix.sh --check
bash spamfox.postfix.sh
```

O instalador salva um snapshot, instala `check_policy_service` no Postfix, roda `postfix check`, executa um smoke de protocolo e recarrega o serviço somente após validação.

## Coletor Rspamd

O instalador antigo de coleta Postfix que usava `content_filter` foi descontinuado: ele precisava reinjetar a mensagem e podia atrasar ou devolver bounce à entrega original. A atualização `spamfox-rspamd.postfix.sh` remove automaticamente esse override de instalações anteriores e não o recria.

```bash
curl -fsSLO https://raw.githubusercontent.com/dgicloud/SPFBL/hadcloud-cpanel-installer/client/spamfox-rspamd.postfix.sh
bash spamfox-rspamd.postfix.sh
```

O script acima é uma migração de segurança. Ele mantém SPFBL, DKIM, SRS e Postfix ativos, mas não coleta conteúdo até que exista um mecanismo de cópia assíncrona validado para o Postfix. Nunca use um `content_filter` para alimentar o Rspamd central.

## Verificação

```bash
postfix check
systemctl is-active postfix
postconf -P 'smtp/inet/content_filter'
```

A última consulta deve retornar `unmatched request`, confirmando que não há filtro SFOX inserido no serviço SMTP.