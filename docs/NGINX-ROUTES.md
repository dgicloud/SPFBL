# Nginx: vhosts e rotas SpamFox

## `matrix.hadcloud.srv.br`

O arquivo-base é `packaging/native/nginx-matrix.conf`. Ele termina TLS em 443 e separa duas funções:

1. **Painel SPFBL**: todas as rotas usuais seguem para `127.0.0.1:8080`.
2. **Gateway Rspamd**: somente `POST /internal/sfox/scan` segue para `127.0.0.1:11335/v1/scan`.

A raiz `/` redireciona para `/pt/`. Links legados que contenham `:8080` são convertidos para HTTPS. O serviço SPFBL não deve ser publicado diretamente em 8080.

## Inclusão do gateway

`packaging/content-scan/install-gateway.sh` localiza o vhost habilitado de `matrix.hadcloud.srv.br` e instala, dentro do bloco `server` HTTPS:

```nginx
include /etc/nginx/snippets/had-sfox-scan-location.conf;
```

O snippet define a rota exata, usa `proxy_request_buffering off`, limita mensagens a 25 MiB e define timeouts restritos. Ele também inclui:

```nginx
include /etc/nginx/snippets/had-sfox-scan-allow.conf;
```

Esse segundo arquivo é gerado por `had-content-scan-sync-allowlist` a partir de `/etc/had-antispam/allowed-cpanels.txt`. Apenas os IPs/CIDRs listados podem chamar o gateway. O endpoint não é público e não recebe autenticação por URL, token de cPanel ou cookie.

## `antispam.hadcloud.srv.br`

Esse vhost é exclusivo da WebUI nativa do Rspamd. Ele deve fazer proxy apenas ao controller/local endpoint configurado para a interface e exigir a autenticação definida no servidor. Não reutilize o vhost `matrix` para expor a WebUI, nem exponha as portas 11333, 11334 ou 6379.

## Validação e rollback

```bash
nginx -t
systemctl reload nginx
curl -i https://matrix.hadcloud.srv.br/
curl -i https://matrix.hadcloud.srv.br/internal/sfox/scan
```

A última chamada, sem corpo e fora da allowlist, deve falhar. No host autorizado, um `GET` de preflight recebe `404` do gateway após passar pelo Nginx; isso prova a rota e a allowlist sem enviar uma mensagem.