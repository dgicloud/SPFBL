# Protocolo SPFBL e contrato de integração

Auditoria de código em 2026-10-01, baseline upstream `7b0232e96f16faca151340b80c418838a800237f`. Os contratos descritos abaixo são os encontrados no código. A integração Exim independente continua em MONITOR: a checagem operacional documentada para o cPanel de homologação confirmou os hooks RCPT e DATA/HEADER, mas as janelas observadas não tiveram uma mensagem que os exercitasse. O utilitário de feedback manual descrito neste documento está apenas no checkout local; não foi instalado no cPanel nem na produção. O resultado dos testes de fixtures está em [evidence/client-protocol-test-notes.md](evidence/client-protocol-test-notes.md).

## Transportes distintos

| Caminho | Transporte real | Evidência |
|---|---|---|
| `spamfox.cpanel.sh` → `spfbl.sh` → core | TCP texto, uma consulta por conexão; padrão cliente `54.233.253.229:9877`, sem TLS | `client/spamfox.cpanel.sh:66-69`; `client/spfbl.sh:36-43,79-83,3686` |
| Adapter HAD em MONITOR | TCP por `127.0.0.1:19877` dentro de túnel SSH restrito; VM encaminha via socket Unix para `core:9877` na rede interna | `integrations/cpanel/had_antispam_client.py`; `packaging/dev/ssh-tunnel-smoke.py`; [laudo do ambiente](DEV-ENVIRONMENT-VALIDATION.md) |
| Integração HAD Postfix em MONITOR | Postfix policy protocol na socket privada `unix:private/had-antispam-policy`; serviço local envia a mesma consulta `SPF` de envelope para o endpoint configurado e responde `DUNNO` | `integrations/postfix/postfix_policy.py`; [instalador Postfix](../integrations/postfix/README.md) |
| Core SPFBL | `ServerSocket(port)`, aceita em todos os endereços do socket; leitura UTF-8, resposta ISO-8859-1, fechamento após resposta | `src/net/spfbl/service/ServerSPFBL.java:98-106,164-179,428-431,1618-1632`, `ServerSPFBL.Connection.run` |
| SPFBLS | TCP/TLS opcional, keystore e hostname necessários; não solicita certificado cliente no código auditado | `ServerSPFBL.java:113-160`, `run()`; `run/spfbl.conf:52-53` |
| `aspf.cpanel.sh` → `spfbl.pl` | SPF local via `Mail::SPF`, DNS e, somente no modo explícito `header` com `licence`, HTTP GET | `client/aspf.cpanel.sh:27-34`; `client/spfbl.pl:168-192,317-350,353-395` |

O core também reconhece Postfix policy (`request=smtpd_access_policy`, pares `chave=valor`, linha vazia final) e `REPORT SPAMC/` na mesma porta. Postfix despacha `RCPT`, `DATA` e `END-OF-MESSAGE`; SPAMC pode transmitir a mensagem MIME completa. Isso não deve ser confundido com a consulta SMTP de envelope. Evidência: `ServerSPFBL.Connection.run`, `ServerSPFBL.java:538-644,777-810`.

## Consulta de envelope

A integração Postfix HAD não usa o policy endpoint nativo remoto do core: o serviço local converte somente o estágio `RCPT` no comando `SPF '<ip>' '<sender>' '<helo>' '<recipient>'`, compartilhado com o cPanel, e mapeia toda resposta para `DUNNO`. Assim ela observa as mesmas decisões sem herdar as rejeições/descarte do cliente Perl upstream. O instalador requer Postfix 3.0+, pois configura `default_action=DUNNO` para quando o processo policy falhar; este requisito e a ordem após proteção relay seguem a documentação oficial do [Postfix policy delegation](https://www.postfix.org/SMTPD_POLICY_README.html). O host Postfix real ainda não está disponível para validação.

O cliente Bash recebe os argumentos na ordem **IP, MAIL FROM, HELO, RCPT TO**, diferente da ordem do cliente Perl (**IP, HELO, MAIL FROM**).

```text
SPF '<ip>' '<sender>' '<helo>' '<recipient>' <exists>\n
```

Exemplo de contrato, usando apenas dados reservados para teste:

```text
SPF '192.0.2.10' 'sender@example.test' 'mx.example.test' 'recipient@example.test' true
```

`exists` pode ser `true`, `false` ou ausente/`null`. O snippet cPanel calcula existência com `verify = recipient`. A resposta é um qualificador, opcionalmente seguido de ticket ou URL. **Não é JSON nem HTTP.** `CHECK` suporta formatos de diagnóstico/legados e não deve ser usado como se fosse a mesma consulta com os mesmos efeitos. Evidência: `client/spfbl.sh:3676-3699`; `client/spfbl_end_recipient:25-56`; `src/net/spfbl/spf/SPF.java:5505-5604`, `SPF.processSPF`.

O parser usa `StringTokenizer` por espaço e retira o primeiro/último caractere das posições entre aspas; reconstrói espaços apenas no remetente. Não é parser genérico de shell, CSV ou SMTP. Remetente vazio torna-se `null`, sender/recipient são convertidos a minúsculas, aspas duplas do destinatário são removidas e subaddress `+` é separado. IP, sender e recipient recebem validações posteriores. Novos adapters devem limitar tamanho e rejeitar CR/LF, NUL e combinações de aspas fora do contrato antes de enviar. Exploração remota de caracteres especiais por Exim permanece **NÃO CONFIRMADA** sem execução da expansão Exim. Evidência: `SPF.java:4888-4889,5517-5544,5622-5631,5646-5686`.

## Cliente registrado e autorização

O cadastro original contém CIDR IPv4/IPv6, domínio descritivo, permissão (`NONE`, `DNSBL`, `SPFBL`; `ADMIN` atribui SPFBL e flag administrativa), email e políticas. A identidade é procurada pelo **IP real do socket**, não pelo IP SMTP passado no payload. O hostname cadastrado não constitui prova DNS, chave ou token. Evidência: `src/net/spfbl/core/Client.java:247-250,274-286,338-368,640-657,843-854,972-1014`; `ServerSPFBL.getClient`, `ServerSPFBL.java:317-332`.

Comando administrativo suportado, a executar futuramente apenas no ambiente privado da administração:

```text
CLIENT ADD <cidr> <hostname> SPFBL [email]
CLIENT SHOW SPFBL
```

Por exemplo, um cPanel precisaria de seu **IP de saída observado pelo core**, ou CIDR mínimo, e hostname identificador. Atrás de NAT, o cadastro não distingue servidores que compartilham o mesmo IP. `CLIENT ADD` é implementado em `src/net/spfbl/core/AdministrationTCP.java:2857-2876`; listagem SPFBL em `2916-2921`; persistência em `Client.java:1090-1140`, `Client.store/load`, arquivo `./data/client.map`.

**O cadastro não é um bloqueio global de consultas neste baseline.** `getClient` pode retornar `null` e `Connection.run` continua para `SPF.processSPF`; `VERSION` responde tanto para clientes registrados quanto para não registrados. Logo, a verificação `spfbl version` do instalador prova conectividade/versão, não autorização. O transporte padrão não usa API key nem mTLS. Prefixo numérico TOTP é reconhecido para alguns comandos e depende de `User`, mas não equivale a autenticação obrigatória de todas as consultas. Evidência: `ServerSPFBL.java:423-431,1054-1075,1596-1602`; `SPF.java:4880-4886`; `client/spamfox.cpanel.sh:69-70,201-208`.

A administração TCP padrão também deve ficar restrita por rede: o listener usa `new ServerSocket(port)` e o caminho inicial chama `processCommand` com `client` possivelmente nulo; o ramo `CLIENT ADD` não contém checagem administrativa própria. Não publicar 9875. Esse risco deve ser validado separadamente em laboratório; não houve ataque a serviço remoto. Evidência: `AdministrationTCP.java:108-118,128-149,312-330,2857-2876`; `run/spfbl.conf:50-53`.

## Qualificadores e ações

“Continuar” na coluna atual significa ausência de `deny/defer/discard` correspondente na ACL RCPT; processamento posterior ainda pode rejeitar, congelar ou marcar. Ações SMTP exatas só estarão comprovadas após `exim -bh`/SMTP na versão cPanel alvo. Os códigos abaixo são os **exits Bash**, não códigos SMTP e não os exits Perl.

| Resposta de `query` | Significado | Exit | Ação atual cPanel | Ação HAD após MONITOR |
|---|---|---:|---|---|
| `PASS <ticket/URL>` | Decisão positiva de envelope; ainda existe análise posterior | 2 | Continuar e acumular ticket | Continuar até Imunify/Rspamd |
| `WHITE <ticket/URL>` | Lista/confiança positiva | 17 | Continuar; HEADER pode confirmar `WHITE` | Continuar com confiança elevada, preservar camadas posteriores |
| `FLAG <ticket/URL>` | Suspeita/negativa a marcar | 16 | Continuar; HEADER `FLAG` adiciona `X-Spam-Status: Yes` | Aceitar e `X-Spam-Flag: YES`, `X-HAD-AntiSpam-Result: FLAG`; entrega Junk exige validação |
| `HOLD <ticket/URL>` | Reter entrega para decisão/feedback | 18 | Continuar; HEADER `HOLD` pode enviar corpo a SPAMC e congelar | Política HAD pendente; em MONITOR apenas observar, sem congelar |
| `GREYLIST` | Atraso temporário de política | 12 | `defer`, texto `4.7.1` | `451 4.7.1 Temporary rejection by HAD AntiSpam` |
| `LISTED [URL]` | Lista temporária, conforme política | 8 | `defer`, texto `4.7.2` | Política pendente; candidato a 451, sem converter automaticamente em BLOCKED |
| `BLOCKED [URL]` | Bloqueio permanente de política | 10 | `deny`, texto `5.7.1` | `550 5.7.1 Message rejected by HAD AntiSpam` |
| `FAIL` sem ticket | SPF falhou e foi decidido rejeitar | 3 | `deny`, texto `5.7.1` | `550 5.7.1 SPF validation failed` |
| `FAIL <ticket>` | Exceção compatível com aceite no contrato cliente | 4 | Continuar como SOFTFAIL, ticket preservado | Não apagar a exceção; confirmar decisão original antes de mapear |
| `SPAMTRAP` | Destinatário trap | 11 | `discard` silencioso | Configurável accept-drop/reject/accept-report; default proposto accept-drop |
| `NXDOMAIN` | Domínio remetente inexistente | 13 | `deny`, texto `5.7.1` | `550 5.1.8 Sender domain does not exist` |
| `INVALID` | IP/remetente/destinatário inválido | 14 | `drop`, texto `5.7.1` | `550 5.7.1 Invalid sender`, motivo estruturado desejável |
| `INVALID <detalhe>` | Erro de contrato/entrada | 7 | `deny`, texto de erro SPF permanente | Distinguir erro de adapter de SMTP inválido; erro interno deve fail-open |
| `SOFTFAIL <ticket>` | Qualificador SPF fraco | 4 | Continuar e acumular ticket | Continuar até Imunify; política de marcação pendente |
| `NEUTRAL <ticket>` | Qualificador SPF neutro | 1 | Continuar e acumular ticket | Continuar |
| `NONE <ticket>` | SPF ausente/resultado sem SPF | 5 | Continuar e acumular ticket | Continuar |
| `LAN` | Rede reservada/local ao cliente | 15 | Continuar; DATA aceita cedo | Continuar respeitando autenticação e filtros existentes |
| `INEXISTENT` | Destinatário inexistente | 19 | `deny`, texto `5.1.1` | Preservar validação recipient do Exim; política HAD pendente |
| `NXSENDER` | Remetente inexistente no contrato legado | 21 | `deny`, texto `5.7.1` | Política pendente; emissão no ramo SPF atual não localizada |
| `BANNED` | Banimento | 22 | `drop`, texto `5.7.1` | Política pendente, MONITOR não derruba conexão |
| `RELEASE <queue-id>` | Liberar mensagem retida | 23/25 | Cliente executa `exim -Mt`; ACL descarta requisição ou nega se fila ausente | Fora do adapter de envelope; preservar somente com autorização separada |
| `REMOVE <queue-id>` | Remover mensagem retida | 24/25 | Cliente executa `exim -Mrm`; ACL descarta requisição ou nega se fila ausente | Fora do adapter de envelope; não executar no MONITOR |
| `TOO MANY CONNECTIONS`, `HOST NOT FOUND` | Erro temporário de capacidade/DNS | 6 | `defer` | Fail-open + log |
| Resposta vazia → `TIMEOUT` | Falha transporte/sem resposta | 9 | `defer` | Fail-open + log |
| `OUT OF SERVICE` | Indisponibilidade | 20 | `defer` | Fail-open + log |
| `ERROR: ...` | Erro servidor, inclusive fatal | 7 | `deny` permanente | Fail-open + log |
| Resposta desconhecida, `TOTP ...`, `SYSTEM SHUTDOWN` | Status sem ramo no cliente | 0 | Continuar, sem garantia de ticket | Fail-open observável; nunca registrar como PASS válido |

Fontes da tabela: `client/spfbl.sh:3701-3775`, ramo `query`; `client/spfbl_end_recipient:57-136`; core `SPF.processSPF`, `SPF.java:5647-5685,5755-5758,6009-6056,6235-6300,6358-6505,6576-6784`; limite de conexões `ServerSPFBL.startService`, `ServerSPFBL.java:169-176`. `NXSENDER` está presente no cliente, mas não foi encontrado como retorno literal no ramo SPF auditado. `FAIL <ticket>` é preservado pelo cliente e pode resultar de qualificador dinâmico; sua ocorrência real exige fixture do core/estado apropriado.

O qualificador positivo não deve ser confundido com SPF RFC puro: o core combina políticas, listas, reputação e resultados SPF. Em especial, `PASS`, `WHITE`, `FLAG` e `HOLD` levam um ticket; preservar o ticket e sua URL original mantém feedback e correlação. Não substituir por um UUID HAD sem adapter explícito.

## Tickets, headers e feedback

A ACL RCPT coleta tickets de PASS/SOFTFAIL/NEUTRAL/NONE/FAIL/FLAG/WHITE/HOLD em lista `;`. DATA envia `HEADER` com ticket(s), DKIM, From, Reply-To, Message-ID/In-Reply-To, Queue-ID, Date, List-Unsubscribe e Subject. Exemplo conceitual do fio:

```text
HEADER <ticket-set> DKIM:<signers> From:<value> Reply-To:<value> Message-ID:<value> Queue-ID:<id> Date:<value> List-Unsubscribe:<value> Subject:<value>
SPAM <ticket-or-url>
HAM <ticket-or-url>
HOLDING <ticket-or-url>
LINK <ticket> <links>
SIGNER <ticket> <signers>
MALWARE <ticket-set> <malware-name>
```

Na alteração local ainda não implantada, a resposta interna RCPT mantém o campo de ticket usado por `HEADER` e acrescenta um sexto campo apenas para feedback humano. Só `PASS`, `WHITE`, `FLAG`, `HOLD`, `SOFTFAIL`, `NEUTRAL` e `NONE` com token completo podem alimentar `X-HAD-AntiSpam-Ticket`; `FAIL` mantém seu ticket no campo original para compatibilidade com `HEADER`, mas não é elegível para esse feedback. O Exim remove qualquer cabeçalho de mesmo nome do remetente em toda transação DATA; só adiciona seu próprio cabeçalho a mensagem recebida em SMTP/25, não autenticada, de IP que não esteja na allowlist de submissão e com um único destinatário. Um operador revisa a mensagem e confirma explicitamente `had-antispam-feedback spam|ham arquivo.eml`; este feedback manual é opcional e separado do autotreino Rspamd. A melhoria não altera o aceite SMTP.

Não enviar corpo no MVP HAD. O cliente upstream oferece `BODY`/`MESSAGE` e a ACL HOLD usa SPAMC, portanto sua instalação integral traz comportamento além da consulta de envelope. Evidência: `client/spfbl_end_recipient:132-136`; `client/spfbl_begin_check_message_pre:21-40,63-80`; `client/spfbl.sh:3190-3248,3260-3368`; `SPF.processSPF`, `SPF.java:4890-4914,5029-5034,5156-5250,5284-5296,5480-5493`.

| Resposta `HEADER` | Exit próprio | Ação DATA atual |
|---|---:|---|
| CLEAR | 0 | Continua na ACL; malware ainda pode rejeitar |
| WHITE | 17 | `accept`, `X-Spam-Status: No` |
| FLAG | 6 | `accept`, `X-Spam-Status: Yes` |
| HOLD | 7 | SPAMC para mensagens <2 MB; em alguns resultados `freeze/no_tell` |
| BLOCKED [URL] | 1 | `deny` |
| REJECT | 5 | `deny` |
| TIMEOUT / OUT OF SERVICE | 2 / 4 | `defer`, portanto não fail-open |
| Desconhecida/erro fatal | 3 | Não há ramo direto de rejeição por exit 3; restante da ACL permanece |

Evidência: `client/spfbl.sh:3216-3248`; `client/spfbl_begin_check_message_pre:41-96`. Não reutilizar os códigos 6/7 de HEADER como se fossem os códigos 6/7 de QUERY.

## Timeout, retry e fail-open

O cliente atual usa `ncat -w 3` e não distingue recusa, erro DNS, serviço sem resposta e timeout: saída vazia vira TIMEOUT. `QUERY_TIMEOUT=10` existe mas não é usado nesse ramo. Não há retry de aplicação em QUERY, apenas o timeout do transporte. Não existe orçamento de 500 ms de conexão/1 s total. DNS adicional no Perl e HTTP de 5 s ampliam ainda mais o limite. Evidência: `client/spfbl.sh:42,79-83,3686-3696`; `client/spfbl.pl:204-206,317-358`.

`MAX_TIMEOUT=256` é comparado ao status de retorno Bash de `incrementTimeout`; esse status tem 8 bits. Com esse default o ramo local OUT OF SERVICE não é alcançado por essa comparação. O contador em `/tmp/SPFBL_TIMEOUT_COUNT` é compartilhado, modo 777 e não tem lock. Os fixtures de contador 255/256 confirmam TIMEOUT. Evidência: `client/spfbl.sh:43,49-75,3688-3694`; [resultados offline](evidence/client-protocol-results.txt).

No servidor, `Connection.drop()` pode encerrar leitura ociosa após um minuto, mas ignora conexão após `QUERY=true`; isso não estabelece deadline total de decisão de 1 s. `spfbl_limit=16` limita slots padrão. Evidência: `ServerSPFBL.java:366-388,1665-1684`; `run/spfbl.conf:64`. Latências P50/P95/P99 são **NÃO CONFIRMADAS**.

**Conclusão: o conjunto upstream cPanel é fail-defer e pode fail-reject para erro interno. Não atende o fail-open obrigatório HAD.** O cliente compartilhado `integrations/common/spfbl_client.py` e o wrapper cPanel mantêm `action=continue` em todos os resultados. Ele valida envelope, usa somente IP literal para não incluir DNS no prazo, limita conexão a 500 ms e consulta ao core a 800 ms, e não executa comandos de fila. Os testes do cliente passaram em Linux/Python 3.6.15 e no cPanel/Python 3.6.8; a suíte atual e a execução remota estão resumidas em [TEST-RESULTS.md](TEST-RESULTS.md). A expansão Exim `4.100.1` em `exim -be` consultou o core real pelo adapter. O hook persistente já foi instalado em MONITOR após `validate`, duas reconstruções/reloads e `healthcheck`; sessão `-bh` ativa confirmou `CONTINUE`. Uma varredura posterior de logs não correlacionou o marcador com uma mensagem SMTP aceita, então o gate de mensagem real/Imunify continua pendente.

O contrato do CLI cPanel é uma linha JSON em `stdin` e uma resposta JSON em `stdout`; o evento em `stderr` omite IP, remetente, destinatário, ticket e resposta bruta. Para Exim, o socket Unix recebe registros tipados de envelope ou metadados DATA. O adapter envia `HEADER <ticket-set> ...` ao core somente quando há ticket validado; devolve ao Exim somente estado/latência e mantém `action=continue`. Smoke Exim 4.98.2 confirmou tickets múltiplos, cabeçalhos, reset entre mensagens, ausência de envio sem ticket e logs sem tokens. No core local, o mesmo serializer enviou um ticket inexistente e recebeu `NOT FOUND`. A checagem operacional em homologação confirmou os hooks RCPT e DATA/HEADER, mas não observou uma transação real que os exercitasse. O cabeçalho HAD de feedback e o CLI que envia `SPAM`/`HAM` após confirmação humana são mudanças locais ainda não instaladas. Veja [README do adapter](../integrations/cpanel/README.md) e [evidência operacional](evidence/production-observation-20261002.md).

## Cliente Perl: contrato separado

`spfbl.pl` não é cliente TCP desse serviço. Ele produz header `Received-SPF` ou Postfix action e retorna: pass=0, fail=1, softfail=2, neutral=3, permerror=4, temperror=5, none=6, accept=7, junk=8, reject=9, defer=10. O snippet MAIL marca exit 8 com `X-Spam-Flag: YES`, rejeita 1/4/9 e adia 5; não trata exit 10. Evidência: `client/spfbl.pl:666-742`; `client/spfbl_end_mail:1-23`.

HTTP opcional lê `/etc/spfbl.conf` apenas quando o quarto argumento é `header`, trata licença como URL e envia dados por GET com timeout de 5 s. A chamada MAIL instalada pelo ASFP usa apenas três argumentos, portanto esse caminho não carrega licença. Falha HTTP por timeout/generic error vira temperror; 429 e connection refused fazem fallback a listas DNS. Não é fail-open uniforme. Evidência: `client/spfbl.pl:168-192,353-395`; `client/spfbl_end_mail:2-3`.

As saídas locais Perl combinam SPF e DNSBL/DNSWL/score externos; `junk/reject/accept` são resultado dessa camada local, não tradução dos qualificadores TCP em maiúsculas. `nxdomain` vira reject. O cliente não recebe RCPT nesse contrato; não oferece a mesma decisão por destinatário/ticket do caminho Bash. Evidência: `client/spfbl.pl:145-201,398-661`; documentação específica em [SPFBL-CPANEL.md](SPFBL-CPANEL.md).

## Verificação ainda exigida

Os 47 fixtures comprovam o parser de resposta Bash. O JAR upstream 1.1.9 isolado gerou os 14 estados, e um ticket PASS válido completou o roundtrip direto `SPAM`/`HAM` (`OK`/`OK`); veja [evidência do core](evidence/core-spf-decision-smoke-20261002.md). Esse ensaio não prova transporte do ticket em `HEADER`/DATA. Testes locais de Exim e do CLI novo cobrem o cabeçalho de ticket e o envio manual autenticado por confirmação, mas ainda falta exercitar o caminho em uma mensagem real controlada; não instalar esse feedback em produção até validar essa prova. Autorização do serviço público, TLS com hostname/certificado real, prazo total, múltiplos destinatários/transações, entrega Junk, Imunify e transporte real do ticket continuam **NÃO CONFIRMADOS**. O rollback do manager e a sobrevivência do hook ao rebuild passaram. O adapter REST e headers HAD são fase posterior, mantendo o protocolo e tickets originais.
