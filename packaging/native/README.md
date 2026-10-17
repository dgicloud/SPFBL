# Pacote nativo SPFBL

Este pacote prepara uma instalação nativa do core SPFBL com serviços systemd, firewall, backup/restore, observabilidade e Nginx. O core e o protocolo SPFBL permanecem upstream; os nomes SpamFox/SFOX pertencem às integrações e à apresentação.

## Uso

Gere o bundle para a release e extraia-o na VM central. Antes da instalação, substitua `matrix.example.com` pelo hostname público e ajuste o e-mail administrativo, as zonas DNSBL e a allowlist de MTAs em `allowed-cpanels.txt`.

```bash
sudo ./install.sh
had-antispam status
```

A VM deve permitir TCP 9877 somente para os IPs públicos autorizados. ADMIN TCP 9875 e backend HTTP 8080 permanecem privados. Publique o painel somente através do Nginx com TLS. O classificador e o gateway de conteúdo usam o Bayes nativo do core e não requerem Rspamd ou Redis.

Consulte [Instalação](../../docs/INSTALLATION.md), [Nginx e rotas](../../docs/NGINX-ROUTES.md) e [Backup](../../docs/BACKUP-RESTORE.md).
