# Adapter de envelope HAD — protótipo MONITOR

Este componente consulta o protocolo TCP original do SPFBL com IP, MAIL FROM, HELO e RCPT TO; quando há ticket válido, também envia metadados da mensagem pelo comando upstream `HEADER` na fase DATA. Continua somente em MONITOR: decisões, erros de transporte/parsing e resultados de `HEADER` não alteram a aceitação do Exim. O estado local mantém apenas tickets validados e metadados transitórios; eventos e logs não incluem cabeçalhos nem tickets. Os hooks RCPT e DATA/HEADER estão instalados no cPanel Grupo Guedes desde 2026-10-02. O adapter foi atualizado para reconhecer o registro `HEADER`; o fake SMTP passou rebuild e reload no Exim 4.100.1. Ainda não há mensagem real observada após instalar DATA, portanto ticket e feedback correlacionados seguem pendentes. Não envia comandos ADMIN, corpo da mensagem nem executa ações de fila.

O cliente usa sintaxe e APIs da biblioteca padrão compatíveis com Python 3.6. Os testes do adapter e do gerenciador passaram no Python 3.6.15/Linux. A validação anterior do cPanel Python 3.6.8 cobriu a versão de 18 testes existente à época. Nesse cPanel, o serviço Unix está instalado como `mailnull:mail`, modo `0660`, e consultou o core real em MONITOR.

No ambiente de desenvolvimento/homologação já validado, o transporte usa o túnel SSH restrito descrito em [DEV-ENVIRONMENT-VALIDATION.md](../../docs/DEV-ENVIRONMENT-VALIDATION.md). Para produção, o destino é o core nativo em `151.242.41.35:9877`: cada cPanel consulta diretamente o listener público, sem túnel. A allowlist nftables da VM deve conter o IP/CIDR de saída de cada cPanel. ADMIN `9875` permanece privado e não é usado pelo cPanel. O protocolo upstream é texto sem TLS e não autentica comandos individualmente; a filtragem por origem é o controle de acesso. O core upstream permanece intacto.

O instalador direto está em `install-client.sh`. Ele testa `VERSION` antes de trocar o adapter de homologação, configura `HAD_SPFBL_HOST`/`HAD_SPFBL_PORT` e inicia o serviço em MONITOR/fail-open. Para instalar os hooks, use `bash integrations/cpanel/install-client.sh --server 151.242.41.35 --port 9877 --activate-acl --test-recipient postmaster@seudominio.com.br`; informe uma caixa local aceita pelo Exim. O smoke usa esse endereço em `exim -bh`, sem enfileirar ou entregar mensagem, valida e reconstrói RCPT e DATA/HEADER e reinicia Exim uma vez. Sem `--activate-acl`, as ACLs não mudam. `rollback-client.sh` retira os hooks HAD gerenciados antes de restaurar o túnel anterior. `update-client.sh` atualiza o adapter preservando endpoint e hooks.

O cliente compartilhado está em `integrations/common/spfbl_client.py`. O entrypoint de cPanel em `had_antispam_client.py` o importa dessa pasta no checkout; qualquer bundle de instalação precisa levar o módulo junto ou instalá-lo ao lado do entrypoint. A integração Postfix usa o mesmo protocolo e o mesmo módulo, com seu próprio handler e instalador: [README Postfix](../postfix/README.md).

### Inventário de caixas postais para suporte


A documentação cPanel descreve `Email/list_pops` para listar caixas postais e `listaccts` para consultar contas WHM ([UAPI](https://api.docs.cpanel.net/openapi/cpanel/operation/list_pops_with_disk/), [API tokens/`listaccts`](https://api.docs.cpanel.net/whm/tokens/)). O agente roda localmente no próprio cPanel para não guardar credenciais WHM no servidor HAD.

## Contrato de entrada e saída

Entrada: uma linha JSON por `stdin`, limitada a 4096 bytes:

```json
{"client_ip":"192.0.2.25","mail_from":"sender@example.test","helo":"mx.example.test","rcpt_to":"recipient@example.test","recipient_exists":true}
```

`recipient_exists` aceita `true`, `false` ou `null`. IP do cliente precisa ser IPv4/IPv6 literal; os outros campos rejeitam controles, CR/LF e aspas simples, pois o protocolo upstream não define escape para esses campos. Limites atuais: IP 45, remetente/destinatário 320 e HELO 255 caracteres. Entrada inválida falha aberta sem enviar consulta.

Saída do CLI: uma linha JSON em `stdout`; um evento JSON resumido em `stderr`. Ambos informam modo, ação, status, qualificador reconhecido, presença de ticket e latência. Não incluem IP, remetente, destinatário, valor do ticket ou resposta bruta. Para o socket local do Exim, uma resposta interna separada leva o ticket validado no quinto campo (`-` quando ausente); esse valor fica somente em variáveis `acl_m_*` da mensagem.

## Prazos e rede

- Endereço do core: `--server` ou `HAD_SPFBL_HOST`; deve ser IP literal para excluir resolução DNS do orçamento.
- Porta: `--port` ou `HAD_SPFBL_PORT`, padrão 9877.
- Conexão ao core: no máximo 500 ms; prazo da consulta ao core: 800 ms; o teste Exim usa `readsocket` com teto de 1 s.
- Toda resposta desconhecida ou falha mantém `action=continue`; o modo não pode ser alterado nesta versão.

## Socket local para Exim

Inicie o serviço com `--listen-socket /run/had-antispam/monitor.sock`. Ele aceita conexões Unix locais e registros separados por Unit Separator (`0x1f`). A consulta RCPT recebe IP, MAIL FROM, HELO, RCPT TO e existência; responde `CONTINUE|status|qualificador|latência_ms|ticket`. O DATA recebe `HEADER`, ticket-set, DKIM e os campos From, Reply-To, Message-ID, In-Reply-To, Queue-ID, Date, List-Unsubscribe e Subject. Só tickets validados são serializados no comando upstream `HEADER`; sem ticket não há conexão ao core. A resposta local DATA contém apenas `CONTINUE|header|estado|latência_ms`. O hook RCPT acumula tickets em `acl_m_had_antispam_ticket_set`; ambos os hooks gravam apenas campos reduzidos. Socket em modo `0660`; no cPanel de homologação o grupo observado é `mail` (usuário `mailnull`).

O adapter usa até 16 consultas simultâneas (o limite configurado do core de laboratório), rejeitando excesso em fail-open; aceita até 64 conexões locais pendentes. A resposta compacta não inclui envelope nem ticket.

O gerenciador RCPT `manage_exim_acl.py` e o DATA `manage_exim_data_acl.py` oferecem `validate`, `install`, `uninstall` e `healthcheck`, cada um com snapshot e rollback próprios. O DATA preserva o hook RCPT existente e exige rebuild válido e fake SMTP que alcance `CONTINUE|header|no_ticket`; `install` requer `--test-recipient` com uma caixa local aceita pelo Exim, pois cPanel pode bloquear `root@localhost` pela política de relay. O smoke com `exim -bh` não enfileira nem entrega mensagens; a prova de tickets e cabeçalhos ocorre separadamente no smoke descartável. Os gerenciadores só editam os hooks Exim; não administram firewall. No cPanel, o firewall é CSF sobre iptables; nftables protege a VM central.

## Testar

Na raiz do repositório:

```bash
python3 -m unittest discover -s integrations/cpanel -p 'test_*.py' -v
python3 -m unittest discover -s integrations/postfix -p 'test_*.py' -v
```

Para consultar o core dentro do namespace isolado do container de desenvolvimento:

```bash
printf '%s\n' '{"client_ip":"192.0.2.25","mail_from":"sender@example.test","helo":"mx.example.test","rcpt_to":"recipient@example.test","recipient_exists":true}' |
  docker run --rm -i --network container:had-antispam-dev-core-1 \
  --mount type=bind,source="$PWD/integrations/cpanel",target=/workspace,readonly \
  --mount type=bind,source="$PWD/integrations/common",target=/common,readonly \
  --entrypoint python python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f \
  /workspace/had_antispam_client.py --server 127.0.0.1
```

O caso acima usa faixa de documentação e deve retornar `LAN` no core atual. O teste real valida apenas essa decisão e transporte; as demais decisões e falhas são simuladas pelos testes unitários. Não execute o comando fora da rede isolada do core sem configurar um endpoint autorizado.

Para provar a integração do socket com Exim sem instalar configuração no servidor real:

```bash
docker build -f packaging/dev/Dockerfile.exim-readsocket -t had-antispam-exim-readsocket-test .
docker run --rm --network container:had-antispam-dev-core-1 had-antispam-exim-readsocket-test
```

Esse teste usa Exim `4.98.2` em um container efêmero. O mesmo snippet RCPT passou no harness fake SMTP com Exim `4.98.2` e com o Exim `4.100.1` do cPanel: quatro RCPT enviaram os campos esperados, incluindo MAIL FROM nulo e nova transação após RSET. Socket ausente e timeout de 1,4 s acionaram fallback; Exim aceitou todos os RCPT. No cPanel, a configuração alternativa temporária usou o prefixo permitido `/etc/exim.conf.*`, o socket `0660` foi criado no grupo observado `mail`, e não restaram diretórios após o teste. Separadamente, `exim -be` com o serviço instalado consultou o core real e retornou `CONTINUE|decision|LAN`; isso valida a expansão, não o hook ativo nem o tráfego SMTP.

Para repetir o harness fake SMTP no Exim descartável:

```bash
docker run --rm --network none --mount type=bind,source="$PWD",target=/workspace,readonly --entrypoint python had-antispam-exim-readsocket-test /workspace/packaging/dev/exim-acl-monitor-smoke.py
```

## Estado atual do hook MONITOR e validação pendente

O hook RCPT existente usa `warn`, continua a ACL em todas as decisões e envia `null` para recipient_exists. O bloco DATA `acl-data-header-monitor.conf` também usa `warn`, envia apenas os metadados upstream quando há ticket e registra somente estado/latência. Smoke Exim 4.98.2 confirmou vários RCPT, headers no comando `HEADER`, isolamento do ticket por mensagem, fail-open sem ticket e logs sem tokens. O core local SPFBL respondeu `NOT FOUND` a um ticket sintético inexistente usando o `HEADER` upstream. No cPanel Grupo Guedes, RCPT e DATA/HEADER estão presentes no hook e configuração Exim; `healthcheck` passou, Exim e adapter estão ativos, e o smoke `exim -bh` passou sem enfileirar mensagem. Após a instalação, ainda não há eventos DATA de tráfego real. Permanecem pendentes mensagem SMTP real identificada, feedback correlacionado e comparação/entrega pelo Imunify.
