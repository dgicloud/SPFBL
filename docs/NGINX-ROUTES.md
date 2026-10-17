# Nginx: vhosts e rotas SpamFox

## `matrix.exemplo.com`

O arquivo-base é `packaging/native/nginx-matrix.conf`. Ele termina TLS em 443 e separa duas funções:

1. **Painel SPFBL**: as rotas usuais, incluindo `/admin/bayes/`, seguem para `127.0.0.1:8080`.
2. **Gateway nativo**: somente `POST /internal/sfox/scan` segue para `127.0.0.1:11335/v1/scan`; o gateway consulta o Bayes do core em loopback.

A raiz `/` redireciona para `/pt/`. Links legados que contenham `:8080` são convertidos para HTTPS. O serviço SPFBL não deve ser publicado diretamente em 8080.

O painel administrativo nativo fica em `/admin/bayes/`, no mesmo vhost. Ele mostra o estado do Bayes, permite classificar EMLs e cadastrar clientes e MTAs pela operação `CLIENT ADD`. A rota e os `POST` exigem sessão de administrador; upload e cadastros só são permitidos quando HTTPS termina no próprio SPFBL ou quando o proxy local envia `X-Forwarded-Proto: https`. O core só confia nesse cabeçalho quando a conexão vem de loopback. O cadastro `CLIENT ADD` não habilita, por si só, pontuação ou decisões Bayes.

## Inclusão do gateway

`packaging/content-scan/install-gateway.sh --hostname matrix.example.com` localiza o vhost habilitado e instala, dentro do bloco `server` HTTPS:

```nginx
include /etc/nginx/snippets/had-sfox-scan-location.conf;
```

O snippet define a rota exata, usa `proxy_request_buffering off`, limita mensagens a 25 MiB e define timeouts restritos. Ele também inclui:

```nginx
include /etc/nginx/snippets/had-sfox-scan-allow.conf;
```

Esse segundo arquivo é gerado por `had-content-scan-sync-allowlist` a partir de `/etc/had-antispam/allowed-cpanels.txt`. Apenas os IPs/CIDRs listados podem chamar o gateway. O endpoint não é público e não recebe autenticação por URL, token de cPanel ou cookie.

## `antispam.exemplo.com`

Esse vhost encaminha para `https://matrix.exemplo.com/admin/bayes/`. O painel aplica a autenticação nativa do SPFBL e exige uma sessão administrativa. O gateway de conteúdo não expõe uma interface própria. Rspamd/Redis não são dependências do fluxo e as portas 11333, 11334 e 6379 não precisam ser abertas.

## Validação e rollback

```bash
nginx -t
systemctl reload nginx
curl -i https://matrix.exemplo.com/
curl -i https://matrix.exemplo.com/internal/sfox/scan
```

O vhost Matrix aceita corpos de até 32 MiB para o gateway de conteúdo e o painel Bayes. O core limita o treinamento a 20 MiB por lote e 5 MiB por arquivo EML.

A última chamada, sem corpo e fora da allowlist, deve falhar. No host autorizado, um `GET` de preflight recebe `404` do gateway após passar pelo Nginx; isso prova a rota e a allowlist sem enviar uma mensagem.
