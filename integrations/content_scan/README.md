# Coletor de conteúdo SpamFox

O coletor é um adaptador pequeno em Python padrão; não instala Java, Rspamd, Redis, bibliotecas de IA nem um segundo MTA. Ele lê a cópia `unseen` entregue pelo Exim em `stdin` e transmite blocos HTTPS à VM central. Não cria arquivo `.eml` ou fila de conteúdo em disco no cPanel.

## Fluxo

1. O Exim recebe DATA e aceita a mensagem normalmente.
2. No primeiro ciclo de entrega, o system filter cria uma cópia `unseen` somente para mensagens SMTP externas não autenticadas. O endereço original mantém sua rota normal.
3. O cliente envia a cópia por HTTPS autenticado para `matrix.hadcloud.srv.br/internal/sfox/scan`. Um lock local limita o upload simultâneo a uma mensagem por cPanel.
4. O Nginx autoriza apenas os IPs da allowlist cPanel, não grava o corpo em arquivo temporário e faz proxy sem request buffering.
5. O gateway valida token e CIDR, limita o corpo a 25 MiB e enfileira a mensagem apenas em RAM. Ele devolve HTTP 202 quando a fila a recebeu; o coletor então termina sem aguardar o resultado Rspamd.
6. Dois workers consultam Rspamd em `127.0.0.1:11333/checkv2` com `Flags: no_log`. Eles registram somente ID de fila do MTA, tamanho, score, ação, símbolos e tempos. Nenhuma ação volta ao Exim/Postfix, SPFBL, reputação ou P2P.

O Exim pode aguardar o upload da cópia depois do aceite SMTP, mas não espera a classificação e não depende dela para entregar a mensagem. Se o gateway estiver cheio, indisponível ou a mensagem exceder 25 MiB, o coletor registra o motivo, retorna sucesso ao Exim e deixa a entrega original seguir. A cópia `unseen` não é repetida se falhar; isso é apropriado ao piloto MONITOR. Mensagens aguardando análise podem ser perdidas quando a VM reiniciar porque a fila central é volátil e não armazena corpos em disco.

O gateway comporta quatro mensagens aguardando e dois workers, com no máximo duas cargas simultâneas. O limite systemd é 384 MiB. A configuração atual do Rspamd limita tarefas a 25 MiB, tem dois workers e timeout de 12 segundos. A análise Bayes não se autotreina: rótulos SPAM/HAM continuam reservados a revisão explícita de operador.

## Preparar a VM central

Com Rspamd/Redis locais ativos em Ubuntu 24.04, instale o gateway como root:

```bash
bash packaging/content-scan/install-gateway.sh
```

O instalador adiciona uma rota exata HTTPS no vhost existente `matrix.hadcloud.srv.br`, cria um serviço preso a loopback e gera o `allow/deny` Nginx da allowlist `/etc/had-antispam/allowed-cpanels.txt`. Não abre porta, reinicia o core SPFBL nem altera Exim/Postfix. O código de API armazena somente hashes de tokens; o token em texto aparece uma vez ao cadastrar cada MTA.

Para criar uma credencial individual, depois de cadastrar o IP de saída no core/allowlist:

```bash
had-content-scan-clients add valinor --cidr 177.39.18.101/32
```

Copie o token exibido diretamente ao cPanel autorizado por um canal seguro. Ao cadastrar novo cPanel, sincronize a allowlist Nginx depois de atualizar a lista do core:

```bash
had-content-scan-sync-allowlist
nginx -t && systemctl reload nginx
```

Revogue um cliente sem tocar no core SPFBL:

```bash
had-content-scan-clients disable valinor
```

## Instalar no cPanel/Exim

O pacote de cPanel leva somente `scan_client.py`, o hook e o instalador. No cPanel, guarde o token num arquivo root-only sem colocá-lo no histórico do shell:

```bash
read -r -s -p 'Token do gateway: ' HAD_SCAN_TOKEN
printf '\n'
umask 077
printf '%s' "$HAD_SCAN_TOKEN" > /root/had-content-scan.token
unset HAD_SCAN_TOKEN
```

Faça primeiro o preflight; depois instale:

```bash
bash install-content-scan.sh --client-id valinor --token-file /root/had-content-scan.token --check
bash install-content-scan.sh --client-id valinor --token-file /root/had-content-scan.token
```

Antes da instalação, configure `system_filter_pipe_transport = address_pipe` em WHM → Service Configuration → Exim Configuration Manager → Advanced Editor → Add additional configuration setting. Use o WHM para salvar e reconstruir o Exim; o instalador não edita manualmente `/etc/exim.conf`. O pacote verifica o transporte e confirma que a conta/grupo do system filter consegue ler o token e obter o lock. A credencial fica em `/etc/had-content-scan/client.json`, root + grupo do filtro, modo `0640`; o cliente e o hook são executados com o usuário do system filter configurado no cPanel. O hook usa a pasta suportada `/usr/local/cpanel/etc/exim/sysfilter/options/`, sem substituir o filtro global.

Para verificar:

```bash
journalctl -u exim --since '10 minutes ago' --no-pager | grep 'had-content-scan'
grep 'had-content-scan' /var/log/exim_mainlog | tail -n 20
```

Os eventos esperados são `upload_queued`, `upload_skipped` ou `request_dropped` no log local, e `message_queued`, `scan_complete` ou `scan_failed` no journal do gateway central. O log nunca inclui assunto, remetente, destinatário ou corpo.

## Limites do estágio

- O gateway está instalado na VM e passou por um smoke com mensagem sintética no Rspamd; o hook e o cliente ainda precisam de smoke em um cPanel de homologação antes de ativar nos demais servidores.
- A verificação não envia assunto, corpo ou anexos ao Jev/OpenRouter; conteúdo vai somente à VM HAD para Rspamd.
- O resultado ainda é observabilidade MONITOR. Marcação, quarentena, rejeição, UI e fluxo de revisão/treinamento não fazem parte desta integração.
- Postfix ainda precisa de um filtro after-queue próprio que preserve a entrega original; não execute o cliente como transport final sem reinjetar a mensagem.
