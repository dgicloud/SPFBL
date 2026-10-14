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
4. Na VM central, libere o IP público de saída do cPanel no core SPFBL e na allowlist do gateway. Crie o perfil pelo IP; o nome interno será gerado automaticamente e o autotreino Bayes conservador ficará ligado por padrão:

   ```bash
   had-content-scan-clients add --cidr IP-PUBLICO/32
   had-content-scan-sync-allowlist
   nginx -t && systemctl reload nginx
   ```

   Se o IP já tiver perfil, use o perfil listado pela CLI para ajustar o autotreino. A entrada do firewall e o perfil devem apontar para o mesmo IP/CIDR; faixas sobrepostas são recusadas.

## Pré-verificação e instalação

Baixe o instalador unificado. Ele detecta cPanel/Exim ou Postfix e usa o pacote de instalação fixado por SHA-256:

```bash
cd /root
curl -fsSLO https://raw.githubusercontent.com/dgicloud/SPFBL/hadcloud-cpanel-installer/client/spamfox-monitor.sh
bash spamfox-monitor.sh --help
```

Substitua a caixa local por uma que o Exim roteia. Primeiro rode a pré-verificação:

```bash
bash /root/spamfox-monitor.sh --test-recipient caixa@seudominio.com.br --check
```

Se passar, instale:

```bash
bash /root/spamfox-monitor.sh --test-recipient caixa@seudominio.com.br
```

O smoke SMTP usa uma transação simulada local e não envia nem entrega e-mail. A instalação exige que a caixa informada exista e seja roteada localmente pelo Exim. O instalador valida as ACLs, o rebuild e o Exim; se uma etapa falha, reverte as alterações desta instalação.

## Verificação após instalar

```bash
systemctl is-active exim
grep 'had-content-scan' /var/log/exim_mainlog | tail -n 20
journalctl -u exim --since '10 minutes ago' --no-pager | grep 'had-content-scan'
```

Na VM central, procure `message_queued` e `scan_complete` no log do gateway. As cópias elegíveis aparecem na History da WebUI Rspamd. O modo é after-queue/monitor: nenhuma ação do Rspamd bloqueia ou altera a entrega SMTP. O treinamento Bayes e o feedback de ticket SPFBL são controlados por cliente na VM central; somente mensagens que passam os critérios de elegibilidade alimentam cada fluxo.

O cliente envia o conteúdo da mensagem para a VM HAD via HTTPS, sem gravar `.eml` no cPanel. Nginx e gateway só aceitam o IP cadastrado; o perfil interno e o autotreino são resolvidos por esse IP. Remova o IP da allowlist/firewall e desative o perfil se o cPanel for removido ou comprometido.

O bundle fica em `/opt/spamfox-cpanel/releases/had-content-scan-cpanel-0.1.15-pilot`. Mantenha esse diretório: os utilitários de gerenciamento da ACL Exim dependem dos arquivos do pacote. O hook SPFBL e o cliente nativo não são removidos pelo instalador deste add-on.
