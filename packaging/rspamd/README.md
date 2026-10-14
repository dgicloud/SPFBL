# Rspamd e Redis centrais

Este pacote instala o Rspamd e Redis somente na VM que hospeda o core SPFBL. Ele não altera Exim, Postfix, portas SMTP nem as regras de firewall dos MTAs.

## Instalação

Execute no checkout do projeto, como `root`:

```bash
bash packaging/rspamd/install-spamfox-rspamd.sh install
```

Opções disponíveis:

```bash
bash packaging/rspamd/install-spamfox-rspamd.sh rspamd-only
bash packaging/rspamd/install-spamfox-rspamd.sh gateway-only
```

O scanner Rspamd (`11333`), o controller (`11334`) e o Redis (`6379`) ficam vinculados ao loopback. O gateway HTTPS recebe somente cópias de mensagens já aceitas e é publicado em `POST /internal/sfox/scan` por Nginx, com allowlist baseada em `/etc/had-antispam/allowed-cpanels.txt`.

## Aprendizagem e feedback SPFBL

O Rspamd usa Bayes nativo e Redis. O gateway admite somente IPs autorizados e só habilita autotreino para perfis explicitamente inscritos. Mensagens autenticadas, sem metadados SMTP suficientes ou fora dos limites conservadores não são usadas para treino.

Quando um perfil também habilita feedback SPFBL, o gateway envia somente `SPAM <ticket>` de uma amostra de alta confiança. Não envia corpo, assunto, score ou credenciais para o SPFBL. Essa etapa melhora a reputação de consultas posteriores; não altera a entrega da mensagem já aceita.

A WebUI nativa do Rspamd permite diagnóstico e treinamento manual pontual de `.eml`. Os auxiliares antigos `had-rspamd-learn` foram descontinuados e não são parte do fluxo suportado.

## Operação

```bash
systemctl status rspamd redis-server had-content-scan-gateway
rspamadm configtest
journalctl -u had-content-scan-gateway -f
```

Para cadastrar a origem de um MTA, primeiro inclua seu IP na allowlist de rede da VM e depois crie um perfil:

```bash
had-content-scan-clients add --cidr IP_PUBLICO/32
had-content-scan-sync-allowlist
nginx -t && systemctl reload nginx
```

A documentação completa do gateway, das rotas e dos limites está em [../../integrations/content_scan/README.md](../../integrations/content_scan/README.md) e [../../docs/NGINX-ROUTES.md](../../docs/NGINX-ROUTES.md).
