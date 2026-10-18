# Pacote nativo SPFBL

Este pacote instala o core SPFBL sem alterar seu código upstream, sob a distribuição SpamFox. Configuração, estado, logs, conta de serviço, comandos e units pertencem ao SpamFox; os avisos de licença e atribuição do SPFBL são mantidos.

O código fica em `/opt/spfbl` e as releases são selecionadas por `/opt/spfbl/current`. O estado mutável fica em `/var/lib/spamfox`, configuração em `/etc/spamfox` e logs em `/var/log/spfbl`. O diretório de logs mantém o nome upstream SPFBL; o usuário e grupo do serviço são `spamfox`.

## Uso

Gere o bundle para a release e extraia-o na VM central, ou use o bootstrap assistido. O assistente coleta hostname público, e-mail administrativo, SMTP, autenticação, fuso horário e allowlist. Configure o DNS e abra TCP 80/443 no firewall antes de solicitar o certificado TLS do Nginx.

```bash
curl -fsSLo install-spamfox.sh https://raw.githubusercontent.com/dgicloud/SPFBL/spamfox/run/install-spamfox.sh
bash install-spamfox.sh
```

O bootstrap instala as dependências de compilação em Debian/Ubuntu, baixa esta branch e abre o assistente. Se já estiver com o bundle extraído:

```bash
sudo ./install-assisted.sh
spamfox status
```

A VM deve permitir TCP 9877 somente para os IPs públicos autorizados. ADMIN TCP 9875 e backend HTTP 8080 permanecem privados. O painel é publicado pelo Nginx com TLS. As mensagens para o Bayes nativo são enviadas pelo usuário no painel web. Na atualização de instalações anteriores, o instalador migra o estado para `/var/lib/spamfox`; se encontrar duas bases com dados, interrompe a migração para evitar mesclá-las.

O administrador também pode gerenciar a allowlist pelo navegador em `/admin/firewall/`, usando a mesma sessão administrativa do core. O auxiliar local de firewall é instalado automaticamente; o processo Java continua sem privilégios de root.

Consulte [Instalação](../../docs/INSTALLATION.md), [Firewall no painel](../../docs/FIREWALL.md), [Nginx e rotas](../../docs/NGINX-ROUTES.md) e [Backup](../../docs/BACKUP-RESTORE.md).
