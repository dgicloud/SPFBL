# Pacote nativo SPFBL

Este pacote prepara uma instalação nativa do core SPFBL com serviços systemd, firewall, backup/restore, observabilidade e Nginx. O core e o protocolo SPFBL permanecem upstream; os nomes SpamFox/SFOX pertencem às integrações e à apresentação.

## Uso

Gere o bundle para a release e extraia-o na VM central, ou use o bootstrap assistido. O assistente coleta hostname público, e-mail administrativo, SMTP, autenticação, fuso horário e allowlist. Configure o DNS e abra TCP 80/443 no firewall antes de solicitar o certificado TLS do Nginx.

```bash
curl -fsSLo install-spamfox.sh https://raw.githubusercontent.com/dgicloud/SPFBL/spamfox/run/install-spamfox.sh
bash install-spamfox.sh
```

O bootstrap instala as dependências de compilação em Debian/Ubuntu, baixa esta branch e abre o assistente. Se já estiver com o bundle extraído:

```bash
sudo ./install-assisted.sh
had-antispam status
```

A VM deve permitir TCP 9877 somente para os IPs públicos autorizados. ADMIN TCP 9875 e backend HTTP 8080 permanecem privados. O painel é publicado pelo Nginx com TLS. As mensagens para o Bayes nativo são enviadas pelo usuário no painel web.

Consulte [Instalação](../../docs/INSTALLATION.md), [Nginx e rotas](../../docs/NGINX-ROUTES.md) e [Backup](../../docs/BACKUP-RESTORE.md).
