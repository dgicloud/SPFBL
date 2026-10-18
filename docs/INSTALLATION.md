# Instalação

O pacote nativo instala o core SPFBL, serviços systemd, firewall, backup/restore, observabilidade e arquivos de exemplo do Nginx. O instalador assistido coleta as configurações da implantação e pode atualizar uma instalação nativa gerenciada ou migrar uma instalação SPFBL legada com backup.

## Instalação assistida em Debian/Ubuntu

Execute como `root`:

```bash
curl -fsSLo install-spamfox.sh https://raw.githubusercontent.com/dgicloud/SPFBL/spamfox/run/install-spamfox.sh
bash install-spamfox.sh
```

O assistente pergunta se a VM receberá uma instalação nova ou atualizará um SPFBL existente. Em seguida, solicita hostname público, allowlist dos MTAs, e-mail administrativo, autenticação do admin, SMTP de saída, fuso horário e configuração opcional do proxy Nginx/TLS. A migração legada cria um backup e preserva o diretório anterior após a atualização.

Antes de selecionar Nginx/TLS, aponte o registro DNS do hostname para a VM e permita TCP 80/443 no firewall da VM e do provedor. Para as consultas, permita TCP 9877 apenas dos IPs públicos dos MTAs. ADMIN TCP 9875 e backend HTTP 8080 permanecem privados.

## Clientes

- [cPanel/Exim](../integrations/cpanel/README.md)
- [Postfix](../integrations/postfix/README.md)

Cadastre cada MTA no core e na allowlist da VM antes da instalação do cliente. Os clientes consultam somente o envelope; não enviam arquivos `.eml`. O Bayes nativo é treinado com mensagens rotuladas pelo painel do SPFBL.

## Validação

```bash
/usr/local/bin/spfbl version
had-antispam status
nginx -t
systemctl is-active had-antispam-core
```

No Postfix, execute também `postfix check`. No cPanel, use as ferramentas do instalador para reconstruir o Exim; não edite o `/etc/exim.conf` gerado manualmente.
