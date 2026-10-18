# Nginx: painel e rotas nativas

Use um hostname próprio, como `matrix.example.com`, com TLS na porta 443. O vhost-base está em `packaging/native/nginx-matrix.conf`.

| Rota | Destino | Acesso |
| --- | --- | --- |
| `/` | Redireciona para `/pt/` | Público |
| `/*` | `127.0.0.1:8080` | Painel nativo SPFBL, protegido pelas contas do core |
| `/admin/bayes/` | `127.0.0.1:8080` | Administração e treinamento global de EML |
| `/admin/firewall/` | `127.0.0.1:8080` | CRUD de IPs/CIDRs de consulta; somente administrador |

O core escuta TCP 9877 para consultas dos MTAs autorizados. A allowlist persistente fica em `/etc/spamfox/allowed-cpanels.txt`; o serviço `spamfox-firewall.service` aplica essa lista. ADMIN TCP 9875 e HTTP TCP 8080 permanecem bloqueados para conexões externas. Nginx acessa a interface HTTP apenas por loopback.

O fluxo nativo de treinamento é o upload de mensagens `.eml` em `/admin/bayes/` ou `/account/bayes/`, com classificação HAM ou SPAM pelo usuário autenticado. Os clientes de e-mail consultam o envelope SPFBL e não transmitem mensagens completas ao core.

Valide e recarregue o Nginx após alterar o vhost:

```bash
nginx -t
systemctl reload nginx
curl -i https://matrix.example.com/
curl -i https://matrix.example.com/pt/
```
