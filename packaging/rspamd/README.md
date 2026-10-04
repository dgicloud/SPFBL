# Rspamd e Redis locais para SpamFox

Este instalador adiciona Rspamd e Redis na VM Ubuntu 24.04 que hospeda o core SPFBL. O scanner HTTP (11333), o controller (11334) e Redis (6379) ficam presos ao loopback. Ele não altera SPFBL, Exim, Postfix, nftables ou portas públicas.

O Bayes usa Redis com schema novo, no mínimo 200 mensagens aprendidas por classe e sem autolearning. Apenas HAM/SPAM revisados por operador devem ser treinados. Redis tem teto de 512 MiB, `noeviction` para preservar os exemplos aprendidos, AOF e limites systemd; Rspamd fica limitado a 1 GiB e dois workers. O scanner recebe mensagens de até 25 MiB e tem limite de processamento de 12 segundos.

Execute como root em Ubuntu 24.04:

```bash
bash install-local.sh
```

O instalador consulta o repositório APT oficial assinado do Rspamd, salva cópias de arquivos tocados em `/var/backups/had-antispam/rspamd/` e recusa substituir configurações locais existentes que não estejam marcadas como gerenciadas pela HAD.

## Estado funcional e próximo trabalho

Essa etapa disponibiliza um scanner local validado para `rspamc` e prepara o backend Bayes/Redis. Ela não recebe ainda mensagens dos cPanels nem Postfix, não classifica e-mail de produção, não aplica ações e não habilita treinamento. O coletor Exim atual não consegue transmitir a mensagem completa pelo hook HEADER; `$message_body` do Exim representa somente um trecho limitado. O próximo passo é o MTA sinalizar apenas o ID da mensagem já aceita e um worker ler e transmitir o conteúdo diretamente, em memória e sob TLS autenticado, para o scanner central. Isso deve ocorrer depois do `250`, sem criar outro arquivo durável `.eml`, sem bloquear a resposta SMTP e sem expor as portas 11333/11334. O cPanel deve continuar baixando apenas o pacote leve do coletor; Rspamd/Redis ficam instalados na VM central.

Para o aprendizado inicial, reunir exemplos legítimos e spam revisados por operador, balanceados; só então treinar com os endpoints privilegiados do controller, usando segredo local root-only. O mínimo configurado é 200 HAM e 200 SPAM antes de considerar o símbolo Bayes útil. Não use classificações automáticas do próprio filtro como rótulos.
