# Instalar o coletor Rspamd no cPanel

`client/spamfox.cpanel.sh` continua sendo o instalador do cliente nativo de reputação SPFBL. Este pacote adiciona o coletor de conteúdo SpamFox/Rspamd e preserva a integração SPFBL que já existe. Ele instala um system-filter `unseen` no Exim, envia uma cópia da mensagem aceita à VM HAD e não muda a decisão de entrega. O Rspamd, Bayes e gateway ficam somente na VM central.

O pacote não inclui core SPFBL, credenciais, mensagens `.eml`, nem instala Rspamd/Redis no cPanel. O código e o pacote preservam a licença e os créditos upstream em `licence.txt`.

## Pré-requisitos

1. O gateway central precisa estar ativo em `https://matrix.hadcloud.srv.br/internal/sfox/scan`.
2. No WHM, abra **Service Configuration → Exim Configuration Manager → Advanced Editor**. Em **CONFIG**, adicione:

   ```exim
   system_filter_pipe_transport = had_sfox_content_pipe
   ```

   Em **TRANSPORTMIDDLE**, cole exatamente este bloco:

   ```exim
   had_sfox_content_pipe:
     driver = pipe
     environment = HAD_SFOX_BSMTP=1:HAD_SFOX_QUEUE_ID_B64=${base64:$message_exim_id}:HAD_SFOX_SENDER_B64=${base64:$sender_address}:HAD_SFOX_RECIPIENTS_B64=${base64:$recipients}:HAD_SFOX_CLIENT_IP_B64=${base64:$sender_host_address}:HAD_SFOX_HELO_B64=${base64:$sender_helo_name}:HAD_SFOX_RECEIVED_PORT_B64=${base64:$received_port}
     message_prefix =
     message_suffix =
     use_bsmtp = true
     return_output
     temp_errors = 75:73
   ```

   Salve no WHM para o cPanel reconstruir o Exim. Não edite manualmente o `/etc/exim.conf` gerado. O mesmo bloco está no arquivo `integrations/cpanel/exim/transport-content-scan.conf` dentro do pacote.
3. Confirme que `exim -bP system_filter_pipe_transport system_filter_user system_filter_group` mostra o transporte dedicado e que o Exim continua ativo.
4. Na VM central, cadastre cada cPanel com um ID próprio e o IP público de saída correto. Habilite autotreino somente para o cliente desejado:

   ```bash
   had-content-scan-clients add ID-DO-CPANEL --cidr IP-PUBLICO/32 --autolearn
   had-content-scan-sync-allowlist
   nginx -t && systemctl reload nginx
   ```

   Se o cliente já estiver cadastrado, ajuste o IP e o autotreino pela CLI central, sem criar credencial duplicada. Cada cPanel deve ter seu próprio token e CIDR.

## Pré-verificação e instalação

Baixe o bootstrap versionado do repositório HADCloud. O script baixa um pacote fixado por SHA-256 para `/opt/spamfox-cpanel/releases/` e mantém os gerenciadores necessários para futuras atualizações e rollback:

```bash
cd /root
curl -fsSLO https://raw.githubusercontent.com/dgicloud/SPFBL/hadcloud-cpanel-installer/client/spamfox-rspamd.cpanel.sh
bash spamfox-rspamd.cpanel.sh --help
```

Crie um arquivo temporário para o token sem colocá-lo em argumentos ou no histórico do shell:

```bash
read -r -s -p 'Token deste cPanel: ' HAD_SCAN_TOKEN
printf '\n'
umask 077
printf '%s' "$HAD_SCAN_TOKEN" > /root/had-content-scan.token
unset HAD_SCAN_TOKEN
chown root:root /root/had-content-scan.token
chmod 0600 /root/had-content-scan.token
```

Substitua o ID e a caixa local por valores reais. Primeiro rode a pré-verificação:

```bash
bash /root/spamfox-rspamd.cpanel.sh --client-id ID-DO-CPANEL --test-recipient caixa@seudominio.com.br --check
```

Se passar, instale:

```bash
bash /root/spamfox-rspamd.cpanel.sh --client-id ID-DO-CPANEL --test-recipient caixa@seudominio.com.br --token-file /root/had-content-scan.token
```

O smoke SMTP usa uma transação simulada local e não envia nem entrega e-mail. A instalação exige que a caixa informada exista e seja roteada localmente pelo Exim. O instalador valida as ACLs, o rebuild e o Exim; se uma etapa falha, reverte as alterações desta instalação.

## Verificação após instalar

```bash
systemctl is-active exim
grep 'had-content-scan' /var/log/exim_mainlog | tail -n 20
journalctl -u exim --since '10 minutes ago' --no-pager | grep 'had-content-scan'
```

Na VM central, procure `message_queued` e `scan_complete` no log do gateway. As cópias elegíveis aparecem na History da WebUI Rspamd. O modo é after-queue/monitor: nenhuma ação do Rspamd bloqueia ou altera a entrega SMTP. O treinamento Bayes e o feedback de ticket SPFBL são controlados por cliente na VM central; somente mensagens que passam os critérios de elegibilidade alimentam cada fluxo.

O cliente envia o conteúdo da mensagem para a VM HAD via HTTPS, sem gravar `.eml` no cPanel. Assunto e corpo são analisados pelo Rspamd central; o gateway registra metadados operacionais sanitizados. Revogue o token na VM se o cPanel for removido ou comprometido.

O bundle fica em `/opt/spamfox-cpanel/releases/spamfox-rspamd-cpanel-0.1.12-pilot`. Mantenha esse diretório: os utilitários de gerenciamento da ACL Exim dependem dos arquivos do pacote. O hook SPFBL e o cliente nativo não são removidos pelo instalador deste add-on.
