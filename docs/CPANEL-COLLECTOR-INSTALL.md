# Instalar coleta técnica no cPanel/Exim

Pacote autocontido: `had-antispam-cpanel-ee7b127.tar.gz`.
O pacote contém scripts, adapter Python 3.6+, hooks, CLI de feedback e licença upstream; não contém credenciais, dados de mensagens, core Java ou chave OpenRouter.

## Antes de instalar

Cadastre o IP público de saída do cPanel com `CLIENT ADD` no core, associado à conta correta, e na allowlist `/etc/had-antispam/allowed-cpanels.txt` da VM. Aplique a allowlist com `systemctl restart had-antispam-firewall.service` na VM. No CSF do cPanel, permita saída TCP 9877 para `151.242.41.35`. Não é necessário abrir uma nova porta de entrada no cPanel.

Este pacote acrescenta coleta em MONITOR e preserva a integração SPFBL de bloqueio já existente. Se não houver integração de bloqueio, ele não a cria: suas ACLs usam warn/fail-open. Não configura firewall, CLIENT, chave Jev ou conta web automaticamente.

## No cPanel, como root

Copie o pacote e seu `.sha256` para `/root`, substitua o endereço abaixo por uma caixa local existente e execute:

```bash
cd /root
sha256sum -c had-antispam-cpanel-ee7b127.tar.gz.sha256
tar -xzf had-antispam-cpanel-ee7b127.tar.gz
cd had-antispam-cpanel-ee7b127
bash install.sh --test-recipient caixa@seudominio.com.br --check
bash install.sh --test-recipient caixa@seudominio.com.br
```

O teste de instalação usa SMTP simulado local e não entrega mensagem. A instalação testa VERSION antes de trocar arquivos, instala o adapter local e os dois hooks, reconstrói/valida Exim e reinicia Exim. Falhas acionam a reversão dos componentes novos; os gerenciadores preservam seus snapshots se uma reversão também falhar. O novo entrypoint recusa sobrescrever cliente já instalado; não use este fluxo como atualização de instalação existente.

## Atualizar cliente existente

Depois de verificar o SHA-256 e extrair o novo pacote, entre no diretório extraído e execute:

```bash
bash integrations/cpanel/update-client.sh
```

Este fluxo atualiza o adapter e reinicia somente o serviço do cliente, preservando o endpoint e os hooks Exim existentes. Para uma instalação nova, use o `install.sh` da raiz conforme acima.
## Conferir

```bash
systemctl is-active had-antispam-client exim
python3 integrations/cpanel/manage_exim_acl.py healthcheck
python3 integrations/cpanel/manage_exim_data_acl.py healthcheck
journalctl -u had-antispam-client --since '10 minutes ago' --no-pager
```

Dados técnicos ficam nos eventos locais do adapter. Nesta versão, somente decisão SPFBL e booleanos de autenticação SMTP/TLS têm origem configurada; os demais sinais continuam desconhecidos até validação no servidor. O registro correlacionável exige mensagem elegível e ticket único. Não há captura de corpo pelo coletor e não há serviço Jev neste cPanel. O HEADER nativo SPFBL existente permanece separado da coleta técnica.

O recebimento central desses eventos e o gatilho calibrado Jev ainda precisam ser implementados; instalar este pacote não ativa análises contínuas de IA. A autenticação de envio dos sinais para a VM pertence a essa etapa futura. Não confundir o segredo HMAC local de correlação com uma credencial de transporte central.

## Análise de conteúdo Rspamd (opcional, pacote separado)

O coletor técnico acima continua sem corpo SMTP. Para o piloto Rspamd, use o pacote leve separado e instale primeiro o gateway central em `packaging/content-scan/install-gateway.sh`. Esse fluxo entrega ao Exim uma cópia `unseen` depois do aceite SMTP, transmite por HTTPS e recebe `202` quando a mensagem entra na fila volátil em RAM. Rspamd analisa depois; nenhuma decisão afeta SPFBL nem a entrega da mensagem. Veja [README do coletor de conteúdo](../integrations/content_scan/README.md) para segurança, credenciais, limites, teste e estado ainda pendente.

## Remover a instalação direta

```bash
bash integrations/cpanel/rollback-client.sh
```

O rollback remove somente os hooks HAD gerenciados e o adapter direto, preservando a integração SPFBL independente. Ele pode restaurar adapter/túnel de desenvolvimento se a instalação registrou que estes estavam habilitados; veja o README incluído. Mantenha o diretório extraído para os gerenciadores e para reversão.
