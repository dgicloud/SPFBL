# Adapter de envelope HAD — protótipo MONITOR

O bundle base mede reputação de envelope e sinais técnicos. A análise de conteúdo completa é um add-on separado: [coletor Rspamd](../content_scan/README.md). Ele não instala Java/Rspamd/Redis no cPanel, mantém o core SPFBL intacto e envia a cópia Exim aceita em stream para o gateway central.

Para novos cPanels, o bundle `1.2.1-had-20261003-signals` inclui um entrypoint raiz `install.sh` que instala adapter e ambos os hooks em uma execução: `bash install.sh --test-recipient caixa@seudominio.com.br`. Use antes `--check` para pré-verificação. Veja [o guia de instalação](../../docs/CPANEL-COLLECTOR-INSTALL.md). Esse fluxo recusa sobrescrever cliente existente e não ativa análises Jev; a coleta técnica ainda permanece local.

Este componente consulta o protocolo TCP original do SPFBL com IP, MAIL FROM, HELO e RCPT TO; quando há ticket válido, também envia metadados da mensagem pelo comando upstream `HEADER` na fase DATA. As decisões continuam em MONITOR e não alteram a aceitação do Exim. Uma melhoria local adiciona o cabeçalho `X-HAD-AntiSpam-Ticket` somente em mensagens de entrada SMTP/25, não autenticadas, fora da lista de IPs de submissão confiável e com um único destinatário. O Exim remove qualquer versão recebida desse cabeçalho em toda transação DATA e só depois adiciona o ticket emitido pelo core quando a mensagem é elegível. O cabeçalho contém o qualificador e um ticket de feedback; quem tem acesso à mensagem também consegue ler o ticket. Isso acompanha o modelo upstream, que incorpora o ticket em `Received-SPFBL` e o extrai do arquivo para enviar `SPAM`/`HAM` ([client/spfbl.sh](../../client/spfbl.sh)). A CLI root-only controla o procedimento de revisão no servidor, mas não torna o cabeçalho invisível ao destinatário. Conforme a [documentação oficial do Exim](https://www.exim.org/exim-html-current/doc/html/spec_html/ch-access_control_lists.html), cabeçalhos adicionados por ACL passam a integrar a mensagem aceita; este instalador não configura remoção posterior por router ou transport. O smoke local prova a adição pela ACL, mas a entrega final em um cPanel real ainda não foi observada. Eventos e logs HAD não incluem o ticket bruto. Mensagens para vários destinatários e mensagens autenticadas não recebem o cabeçalho. Não envia comandos ADMIN, corpo da mensagem nem executa ações de fila.

O cliente usa sintaxe e APIs da biblioteca padrão compatíveis com Python 3.6. Os testes do adapter e do gerenciador passaram no Python 3.6.15/Linux. A validação anterior do cPanel Python 3.6.8 cobriu a versão de 18 testes existente à época. Nesse cPanel, o serviço Unix está instalado como `mailnull:mail`, modo `0660`, e consultou o core real em MONITOR.

No ambiente de desenvolvimento/homologação já validado, o transporte usa o túnel SSH restrito descrito em [DEV-ENVIRONMENT-VALIDATION.md](../../docs/DEV-ENVIRONMENT-VALIDATION.md). Para produção, o destino é o core nativo em `151.242.41.35:9877`: cada cPanel consulta diretamente o listener público, sem túnel. A allowlist nftables da VM deve conter o IP/CIDR de saída de cada cPanel. ADMIN `9875` permanece privado e não é usado pelo cPanel. O protocolo upstream é texto sem TLS e não autentica comandos individualmente; a filtragem por origem é o controle de acesso. O core upstream permanece intacto.

O instalador direto está em `install-client.sh`. Ele testa `VERSION` antes de trocar o adapter de homologação, configura `HAD_SPFBL_HOST`/`HAD_SPFBL_PORT` e inicia o serviço em MONITOR/fail-open. Para instalar os hooks, use `bash integrations/cpanel/install-client.sh --server 151.242.41.35 --port 9877 --activate-acl --test-recipient postmaster@seudominio.com.br`; informe uma caixa local aceita pelo Exim. O smoke usa esse endereço em `exim -bh`, sem enfileirar ou entregar mensagem, valida e reconstrói RCPT e DATA/HEADER e reinicia Exim uma vez. Sem `--activate-acl`, as ACLs não mudam. `rollback-client.sh` retira os hooks HAD gerenciados antes de restaurar o túnel anterior. `update-client.sh` atualiza o adapter preservando endpoint e hooks.

Para distribuir uma versão autocontida a outros cPanels, gere o arquivo com `pwsh -File packaging/cpanel/build-bundle.ps1 -Version 1.0.0`. O pacote inclui o cliente compartilhado, hooks, helper de feedback, scripts de instalação/atualização/rollback e `licence.txt`; o arquivo `.sha256` acompanha o bundle. Extraia o arquivo no cPanel e execute os scripts a partir do diretório extraído para preservar a estrutura relativa esperada. O bundle não inclui dados de produção, credenciais nem o core SPFBL.

### Feedback manual por ticket

O feedback não é automático. Um operador deve revisar a mensagem completa e executar o comando explicitamente. O utilitário `had-antispam-feedback` é instalado em `/usr/local/sbin`, executa como root, pede confirmação interativa e lê somente o cabeçalho `X-HAD-AntiSpam-Ticket` do arquivo `.eml`:

```bash
sudo had-antispam-feedback spam /caminho/mensagem.eml
sudo had-antispam-feedback ham /caminho/mensagem.eml
sudo journalctl --since "7 days ago" --no-pager -o cat | sudo had-antispam-feedback report -
```

Ele usa o endpoint numérico protegido em `/etc/had-antispam/client.conf` e envia uma única chamada nativa `SPAM <ticket>` ou `HAM <ticket>` ao core. O ticket não aparece nos argumentos do processo, na saída nem no log de auditoria. No primeiro envio, o utilitário cria `/etc/had-antispam/feedback-hmac.key` como segredo aleatório de 32 bytes, root-owned e modo `0600`; o syslog registra um HMAC-SHA-256 do ticket, não o ticket bruto. Esse identificador pseudônimo fica local no cPanel e não é enviado ao core nem ao Jev. Ele permite deduplicar mensagens dentro desse servidor, mas continua correlacionável nos logs enquanto a mesma chave for mantida. Timeout é reportado como resultado incerto; não há repetição automática, pois o core pode já ter registrado a primeira tentativa. Use `spam` apenas após confirmar spam; `ham` serve para corrigir uma denúncia indevida. Essas ações alteram o estado do SPFBL e podem contribuir com reputação P2P.

O ticket é incluído apenas para uma mensagem SMTP de entrada com um único destinatário. O protocolo Exim aplica alterações de cabeçalho ao nível da mensagem; essa restrição evita usar o ticket de um destinatário para treinar os demais destinatários da mesma mensagem. Exportar `.eml` com o cabeçalho ausente, múltiplo ou alterado falha fechado e não envia feedback.

`report` agrega os eventos syslog sem imprimir as linhas originais, endereços, tickets ou HMACs. Mantém métricas por evento, `latest_accepted_ticket_label_groups` por grupos e `latest_accepted_ticket_labels_by_decision` por qualificador original (por exemplo, separa `FLAG` de `HOLD`); ambas as visões deduplicadas usam o último rótulo aceito na ordem das linhas, e `unchanged` não substitui o rótulo. `operator_override_indicators` conta revisões `HAM` para `FLAG`/`HOLD` e revisões `SPAM` para `PASS`/`WHITE`, para orientar inspeção das regras. Esses contadores não são taxas de falso positivo/negativo: a revisão é escolhida pelo operador, não é uma amostra aleatória, e não calibra o limiar Jev. `tickets_with_corrected_labels` conta tickets que receberam ações aceitas `SPAM` e `HAM`. Eventos antigos sem HMAC continuam apenas nas métricas de evento. `OK` confirma processamento do protocolo, não mudança de contador de reputação nem entrega ao peer.

`dataset` gera JSONL local com rótulo de feedback aceito e apenas os dez campos técnicos enumerados. O cabeçalho informa balanço de HAM/SPAM, cobertura conhecida por campo, quantidade de padrões técnicos distintos, schema e limitações; cada amostra omite ticket, HMAC, destinatário, remetente, assunto, corpo, IP e timestamp. O comando não faz rede nem chama Jev. Use apenas para avaliação local e proteja o arquivo exportado:

```bash
sudo sh -c 'umask 077; journalctl --since "7 days ago" --no-pager -o cat | /usr/local/sbin/had-antispam-feedback dataset - > /root/had-antispam-feedback.jsonl'
```

Os rótulos são revisões selecionadas pelos operadores, não uma amostra representativa nem verdade-terreno. O arquivo não está calibrado e não deve ser usado para alegar precisão/recall ou ativar decisões automáticas. Ainda será preciso reunir volume e diversidade adequados, definir retenção e avaliar em uma separação temporal independente antes de treinar ou calibrar qualquer escore.

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
- Conexão ao core: tentativas de até 500 ms, com uma repetição somente antes de enviar o comando; o prazo total continua limitado a 800 ms e o `readsocket` do Exim a 1 s. A telemetria distingue falha de conexão de timeout/erro ao enviar ou ler e registra `connect_attempts`; o fluxo segue fail-open.
- Toda resposta desconhecida ou falha mantém `action=continue`; o modo não pode ser alterado nesta versão.

## Socket local para Exim

Inicie o serviço com `--listen-socket /run/had-antispam/monitor.sock`. Ele aceita conexões Unix locais e registros separados por Unit Separator (`0x1f`). A consulta RCPT recebe IP, MAIL FROM, HELO, RCPT TO e existência; responde `CONTINUE|status|qualificador|latência_ms|ticket|feedback`. O último campo só contém `QUALIFICADOR ticket` para tickets completos e classes aceitas por `SPAM`/`HAM`; caso contrário contém `-`. O DATA recebe `HEADER`, ticket-set, DKIM e os campos From, Reply-To, Message-ID, In-Reply-To, Queue-ID, Date, List-Unsubscribe e Subject. O registro local tem um esquema fixo com dez campos técnicos; por segurança entre compilações Exim, o checkout preenche apenas a decisão SPFBL, autenticação SMTP e TLS, mantendo SPF, DKIM, DMARC, Rspamd e reverse DNS desconhecidos até validação no cPanel. Esses sinais são normalizados e nunca entram no comando upstream `HEADER`, que mantém o protocolo SPFBL existente. Só tickets validados são serializados; sem ticket não há conexão ao core. A resposta local DATA contém apenas `CONTINUE|header|estado|latência_ms`. O hook RCPT acumula tickets em `acl_m_had_antispam_ticket_set`; logs de consulta omitem os tickets. O evento técnico local só é gravado com ticket único e decisão elegível para feedback manual; contém apenas enums/booleanos e um HMAC-SHA-256 do ticket. Socket em modo `0660`; no cPanel de homologação o grupo observado é `mail` (usuário `mailnull`).

O instalador cria `/etc/had-antispam/signals-hmac.key` como `root:mail`, modo `0640`, para que o adapter `mailnull:mail` possa gerar o mesmo pseudônimo que o CLI root-only. `/etc/had-antispam` fica `root:mail`, modo `0750`; os arquivos de configuração e a chave existente de auditoria continuam `root:root`, modo `0600`. O rollback preserva a chave de sinais: removê-la impediria correlacionar os registros históricos. O relatório `had-antispam-feedback report ARQUIVO_DE_LOG` agora relaciona rótulos aceitos manualmente aos sinais técnicos mais recentes por esse identificador e retorna apenas agregados.

O adapter usa até 16 consultas simultâneas (o limite configurado do core de laboratório), rejeitando excesso em fail-open; aceita até 64 conexões locais pendentes. A resposta compacta não inclui envelope nem ticket.

O gerenciador RCPT `manage_exim_acl.py` e o DATA `manage_exim_data_acl.py` oferecem `validate`, `install`, `uninstall` e `healthcheck`, cada um com snapshot e rollback próprios. Se as opções `acl_custom_begin_recipient` ou `acl_custom_begin_check_message_pre` estiverem ausentes de `exim.conf.localopts`, o gerenciador as acrescenta para o rebuild e remove no rollback/desinstalação, preservando o estado original do arquivo. O DATA preserva o hook RCPT existente e exige rebuild válido e fake SMTP que alcance `CONTINUE|header|no_ticket`; `install` requer `--test-recipient` com uma caixa local aceita pelo Exim, pois cPanel pode bloquear `root@localhost` pela política de relay. O smoke com `exim -bh` não enfileira nem entrega mensagens; o harness descartável também extrai o ticket do cabeçalho gerado pelo Exim e exercita o CLI com um core TCP falso. Os gerenciadores só editam os hooks Exim; não administram firewall. No cPanel, o firewall é CSF sobre iptables; nftables protege a VM central.

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

O hook RCPT existente usa `warn`, continua a ACL em todas as decisões e envia `null` para recipient_exists. O bloco DATA/HEADER também usa `warn`, preserva a consulta `HEADER` original e envia o esquema técnico fixo apenas ao adapter local. O smoke com Exim 4.98.2 passou com 21 campos, incluindo decision SPFBL e estados de autenticação/TLS; as expansões SPF/DKIM/DMARC foram deixadas vazias para permanecer compatível com builds Exim que não as oferecem. As variáveis efetivamente disponíveis ainda precisam de validação num cPanel ativo. O harness de feedback exercita CLI e um core TCP descartável, sem mensagem real. No cPanel Grupo Guedes, a versão previamente observada tinha RCPT e DATA/HEADER no hook, mas as janelas não tiveram mensagem real que exercitasse DATA. Em 2026-10-03, os módulos, a coleta técnica e o CLI foram instalados no Grupo Guedes em MONITOR, com snapshot e ambos os healthchecks aprovados; Jev continua desconectado. O smoke Exim 4.100.1 e os 86 testes Python 3.6.8 passaram no próprio cPanel. Permanecem pendentes mensagem SMTP remota real, registro correlacionado dos sinais e vínculo com feedback humano aceito. Veja docs/evidence/cpanel-signals-deployment-20261003.md.
