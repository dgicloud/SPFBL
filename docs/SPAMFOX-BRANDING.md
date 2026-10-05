# Identidade SpamFox no lado do cliente

Esta primeira etapa aplica a identidade SpamFox somente às mensagens operacionais exibidas nos servidores de e-mail:

- ACLs Exim de cPanel e DirectAdmin: logs como `SFOX check blocked`, `SFOX check banned` e `SFOX check timeout`; respostas SMTP identificam `SpamFox (SFOX)`.
- Postfix: respostas da policy client usam `SpamFox (SFOX)` para bloqueio, banimento, greylisting e falhas.
- O coletor cPanel em modo MONITOR registra `SFOX MONITOR` no `exim_mainlog`.
- Saídas visíveis dos instaladores cPanel e DirectAdmin chamam o produto de `SpamFox (SFOX)`.

O core SPFBL, o cliente de protocolo, os comandos, estados de resposta, nomes de ACL/variáveis, headers `Received-SPFBL`, paths, arquivos de serviço e integração de rede continuam como estão. Os templates ACL exibidos pelos instaladores cPanel e DirectAdmin vêm do repositório HAD; o restante do cliente e os créditos/licença GPL do SPFBL permanecem preservados. Links de feedback oficiais continuam apontando para SPFBL.net.

Exemplo de resposta ao remetente:

```text
550 5.7.1 SpamFox (SFOX) permanently blocked.
```

Log Exim correspondente:

```text
SFOX check blocked.
```

Esta etapa não altera páginas web, logo, favicon, headers de mensagem nem branding do core. A instalação atual usa a branch `dgicloud/SPFBL:hadcloud-cpanel-installer` para os templates; a publicação em um repositório próprio SpamFox fica separada desta alteração local.
