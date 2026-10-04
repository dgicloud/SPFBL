# Coletor de conteúdo Rspamd para Postfix

Este é o cliente leve de conteúdo do SpamFox para Postfix. Ele é separado da integração de policy SPFBL: `install.sh` continua instalando apenas a policy de envelope; para conteúdo, use os scripts `*-content-scan.sh` deste diretório.

## Fluxo seguro do piloto

1. O Postfix recebe e enfileira a mensagem pelo SMTP de entrada.
2. Apenas o serviço `smtp/inet/smtpd` recebe um transporte `pipe` after-queue. O processo roda como usuário sem login `had-content-scan` e recebe uma cópia do conteúdo.
3. O cliente retransmite os mesmos bytes ao `sendmail` local para a entrega normal e envia, em paralelo, uma cópia HTTPS autenticada ao gateway Rspamd. Há no máximo duas cópias simultâneas, limitadas por duas travas locais e pelo limite do transporte Postfix; o cliente não grava outro arquivo `.eml`.
4. Falha ou timeout do gateway deixa a entrega original seguir. Se a reinjeção local falhar, o filtro retorna erro temporário para que o Postfix tente novamente.
5. A classificação fica em MONITOR: score e ação do Rspamd não rejeitam, retêm, alteram a mensagem nem atualizam reputação SPFBL/P2P. Se as duas vagas de cópia estiverem ocupadas, o conteúdo daquela mensagem é ignorado para análise e a entrega continua. Bayes só aprende de amostras explicitamente revisadas.

O gateway guarda mensagens aguardando análise apenas em RAM. Uma reinicialização pode perder a cópia de análise, sem cancelar a entrega original já reinjetada. O Postfix precisa estar na versão 3.0 ou superior. A integração recusa `content_filter` global e filtros já configurados no serviço SMTP porque ainda precisam ser encadeados manualmente.

O desenho segue o [guia oficial de filtros after-queue do Postfix](https://www.postfix.org/FILTER_README.html), que documenta a reinjeção via `sendmail -G -i` e o isolamento do transporte. Os parâmetros do pipe seguem [pipe(8)](https://www.postfix.org/pipe.8.html); em particular `null_sender=` vazio preserva corretamente o remetente nulo.

## Preflight e instalação

Cadastre primeiro um client ID e um token exclusivo para o IP/CIDR público de saída deste MTA na VM, usando `had-content-scan-clients add`. Transfira o token diretamente ao servidor autorizado. Não reutilize token de cPanel ou de outro Postfix.

No Postfix, coloque o token em arquivo root-only sem passá-lo na linha de comando:

```bash
umask 077
read -r -s -p 'Token do gateway: ' HAD_SCAN_TOKEN
printf '\n'
printf '%s' "$HAD_SCAN_TOKEN" > /root/had-content-scan.token
unset HAD_SCAN_TOKEN
chmod 600 /root/had-content-scan.token
```

Extraia o bundle mantendo `integrations/postfix` e `integrations/content_scan` lado a lado. Antes de alterar qualquer configuração, rode o preflight:

```bash
cd integrations/postfix
sudo bash ./validate-content-scan.sh
```

Instale sem recarregar Postfix; o instalador guarda snapshot, configura o transporte apenas no serviço SMTP de entrada, instala o cliente e executa `postfix check`:

```bash
sudo bash ./install-content-scan.sh \
  --client-id nome-do-mta \
  --token-file /root/had-content-scan.token
```

Revise `/etc/postfix/master.cf` e ative em etapa separada:

```bash
sudo bash ./activate-content-scan.sh
sudo bash ./healthcheck-content-scan.sh
```

O preflight e o healthcheck não enviam mensagens. O healthcheck confirma a configuração gerenciada e `postfix check`; para validar o caminho de ponta a ponta, aguarde uma mensagem externa legítima a um destinatário local autorizado e confira os logs do gateway e do MTA. Não envie conteúdo sintético a destinatários de clientes.

## Logs e remoção

Os eventos locais incluem `upload_queued`, `upload_skipped` e `reinject_deferred`; o conteúdo, assunto, remetente e destinatário não são registrados. Consulte o journal/syslog do Postfix segundo a distribuição e, na VM, `journalctl -u had-content-scan-gateway.service`.

A remoção recompõe os arquivos originais e exige re-enfileirar toda a fila para limpar referências ao transporte salvo nos queue IDs. Faça isso em uma janela operacional:

```bash
sudo bash ./uninstall-content-scan.sh --reload --requeue-all
```

Se alguém editar arquivos gerenciados após a instalação, o removedor para e preserva o snapshot em `/var/lib/had-content-scan/postfix-install/current` para evitar sobrescrever alterações administrativas.

## Estado e limitações

- O piloto real foi validado no Enhance/Postfix `177.39.18.105`: mensagens recebidas seguiram pelo transporte after-queue, foram reinjetadas e tiveram entrega LMTP confirmada. A coleta de 24 horas identificou nove cópias ignoradas pela trava serial anterior; o coletor agora permite até duas cópias simultâneas, igual ao limite do transporte e do gateway. Isso não substitui observação de carga contínua ou avaliação estatística.
- Regras de score não são treinamento Bayes. O contador atual é 0 amostras revisadas; o classificador só começa a contribuir depois de 200 HAM e 200 SPAM revisados.
- Nenhum assunto ou corpo é enviado ao Jev/OpenRouter. O conteúdo segue somente ao Rspamd local na VM HAD.
- As actions Rspamd não controlam entrega. Marcação, quarentena e rejeição exigem validação posterior de falsos positivos e autorização operacional separada.
