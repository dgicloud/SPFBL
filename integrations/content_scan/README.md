# Gateway de conteúdo e Rspamd

O gateway recebe cópias de mensagens que já foram aceitas pelo MTA, faz fila somente em RAM e encaminha ao Rspamd local. Ele nunca participa da resposta SMTP do cliente.

## VM central

Requisitos: Ubuntu 24.04, core SPFBL nativo ativo, Nginx funcional para `antispam.exemplo.com` e `/etc/had-antispam/allowed-cpanels.txt` contendo os IPs públicos dos MTAs.

```bash
cd /opt/spfbl
bash packaging/rspamd/install-spamfox-rspamd.sh install
```

O instalador configura Rspamd + Redis no loopback, instala o gateway em `127.0.0.1:11335`, adiciona a rota Nginx e valida `rspamadm configtest`, Nginx e systemd.

## Rota HTTPS e Nginx

| Rota | Destino | Acesso |
|---|---|---|
| `POST /internal/sfox/scan` | `127.0.0.1:11335/v1/scan` | Apenas IPs em `allowed-cpanels.txt` |
| `/` em `matrix.hadcloud.srv.br` | painel SPFBL em `127.0.0.1:8080` | HTTPS público, raiz redireciona para `/pt/` |
| `https://antispam.hadcloud.srv.br/` | WebUI Rspamd | conforme autenticação do vhost |

O snippet `packaging/content-scan/had-sfox-scan-location.conf` contém os limites de corpo, timeouts e `proxy_request_buffering off`. O vhost principal está em `packaging/native/nginx-matrix.conf` e inclui o snippet no servidor HTTPS de `matrix.hadcloud.srv.br`.

## Clientes e aprendizagem

A admissão ocorre por IP: o gateway cruza o IP remoto com a allowlist usada pelo SPFBL. Não há ID de cPanel, token ou credencial por MTA. Para criar um perfil explícito e sincronizar Nginx:

```bash
had-content-scan-clients add --cidr IP_PUBLICO/32
had-content-scan-sync-allowlist
nginx -t && systemctl reload nginx
```

O Rspamd aprende somente amostras elegíveis e de alta confiança. Quando o perfil habilita feedback SPFBL e existe ticket válido, o gateway pode emitir `SPAM <ticket>` ao core; ele envia ticket, não corpo, assunto ou score. A análise posterior não bloqueia a primeira mensagem: ela melhora classificação e reputação das próximas.

## Operação

```bash
systemctl status rspamd redis-server had-content-scan-gateway
journalctl -u had-content-scan-gateway -f
```

A WebUI nativa do Rspamd é o local para analisar e ensinar manualmente arquivos `.eml`. Os corpos enviados pelo gateway não são persistidos pelo gateway depois da análise.