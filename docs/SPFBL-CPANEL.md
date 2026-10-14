# Auditoria da integração SPFBL com cPanel/Exim

Auditoria de código: 2026-10-01. Baseline upstream `7b0232e96f16faca151340b80c418838a800237f`. A auditoria abaixo descreve o comportamento upstream e seus limites. **Atualização operacional em 2026-10-02:** por solicitação do usuário, o instalador upstream foi executado no cPanel de homologação com o endpoint alterado para `203.0.113.10`; suas ACLs estão ativas e uma mensagem real anterior foi temporariamente adiada por greylisting. O firewall desse cPanel é CSF/iptables. O adapter e o hook HAD próprio estão instalados em MONITOR. Uma varredura de logs encontrou um resultado `CONTINUE|decision|LAN`, sem correlação suficiente com uma transação SMTP aceita; envio/entrega com observação Imunify permanecem pendentes. Consulte o [laudo operacional atualizado](NATIVE-DEPLOYMENT-REPORT.md).

## Conclusão operacional

**Conclusão de desenho:** o código upstream oferece integração em RCPT, porém pode adiar mensagens quando o SPFBL está fora, rejeitar erro interno, modificar filtros existentes e instalar regras/scripts de firewall. Ele não atende aos requisitos HAD de fail-open e rollback exato. A execução na homologação foi um teste de compatibilidade explicitamente solicitado; não substitui a integração HAD MONITOR/fail-open nem comprova que o fluxo upstream possa ser distribuído sem avaliação operacional.

É possível reutilizar o protocolo e o core mantendo os tickets, com um adapter próprio e ACL RCPT mínima. A instalação persistente MONITOR, coexistência dos serviços e rebuild foram validados na homologação; falta comprovar uma transação SMTP identificada de ponta a ponta, a entrega e a classificação do Imunify antes de avaliar qualquer enforcement HAD.

## Dois caminhos upstream diferentes

| Componente | Instalador | Estágio principal | Rede | Destinatário/tickets |
|---|---|---|---|---|
| `client/spfbl.pl` | `client/aspf.cpanel.sh` | MAIL FROM | SPF local, DNS público; HTTP opcional via licença | Chamada instala apenas IP/HELO/sender; sem RCPT/ticket TCP |
| `client/spfbl.sh` | `client/spamfox.cpanel.sh` | RCPT TO + DKIM + DATA | TCP SPFBL; SPAMC adicional em HOLD | Envia IP/sender/HELO/recipient/existência, acumula tickets |

Evidência: `client/aspf.cpanel.sh:26-40`; `client/spfbl_end_mail:1-23`; `client/spamfox.cpanel.sh:66-69,144-188`; `client/spfbl_end_recipient:25-56`; `client/spfbl_begin_check_message_pre:21-40,77-96`. A solicitação de auditar `spfbl.pl` não significa que esse seja o cliente usado pelo instalador SPFBL atual.

## Onde o instalador escreve

| Local no cPanel | Origem/conteúdo | Efeito |
|---|---|---|
| `/usr/local/bin/spfbl` | Download de `master/client/spfbl.sh` | Cliente Bash configurado para IP externo e TCP claro |
| `/usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/spfbl_end_recipient` | Snippet RCPT | Consulta/nega/adia/descarta por destinatário |
| `/usr/local/cpanel/etc/exim/acls/ACL_SMTP_DKIM_BLOCK/spfbl_begin_smtp_dkim` | Snippet DKIM | Acumular signers, com defeito auditado abaixo |
| `/usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/spfbl_begin_check_message_pre` | Snippet DATA | HEADER, malware, SPAMC, flags e freeze |
| `/etc/exim.conf.localopts` | `exim_configuration` via sed/append | Habilita snippets e muda opções existentes |
| `/etc/exim.conf.local` | sed/substituição/append | `timeout_frozen_after=7d`, `spamd_address=54.233.253.229 9877 retry=30s tmo=3m`, `smtp_accept_max=250` |
| `/etc/clamav-unofficial-sigs/` + `/usr/local/bin/clamav-unofficial-sigs.sh` | Downloads GitHub e assinatura matrix | Instala conteúdo/scanner e cron/logrotate adicionais |
| `/etc/cron.hourly/spfbl-holding-check` | `/usr/local/bin/spfbl holding` | Libera/remove/altera mensagens da fila conforme resposta |
| `/usr/local/bin/spfbl-firewall-update`, `/usr/local/bin/spfbl-firewall`, cron e `/etc/csf/csfpost.sh` | Downloader/gerador de firewall | Regras iptables, script remoto executado |

Evidência: `client/spamfox.cpanel.sh`, `exim_configuration:26-35`, `install:66-79,139-199`, `firewall:301-307`; `client/firewall.cpanel.sh:8-47`.

O script checa `/usr/local/cpanel/cpanel -V`, instala dependências se `nmap` estiver ausente e usa `spfbl version` como gate. Não checa explicitamente Exim, Imunify ou SpamAssassin; tampouco verifica que `ncat` exista se `nmap` já estava instalado. Downloads usam branches mutáveis, sem assinatura/checksum/pin. `wget` escreve diretamente nos destinos, sem staging atômico. Não há backup, validação de sintaxe Exim prévia, `set -e`/trap de rollback ou inspeção de cada retorno. Evidência: `client/spamfox.cpanel.sh:37-70,144-188,212-250`.

## Persistência em cPanel

O instalador não edita `/etc/exim.conf` diretamente; usa `.local`, `.localopts`, diretórios de ACL e chama `buildeximconf`. Isso mostra a intenção de persistência, não prova de que snippets sejam carregados em toda versão. Os nomes upstream não têm prefixo `custom_`, enquanto a documentação atual descreve ACLs customizadas nesse diretório com `custom_*`. O instalador Perl ainda menciona no comentário um arquivo `custom_end_mail_spfbl` que não existe neste checkout; o instalador ASFP usa `spfbl_end_mail`. Evidência: `client/spamfox.cpanel.sh:145-188`; `client/aspf.cpanel.sh:32-34`; `client/spfbl.pl:43-54`.

A documentação oficial confirma que `exim.conf` é gerado das configurações cPanel e que modificações diretas podem ser sobrescritas. O mecanismo custom ACL é candidato adequado ao pacote HAD, mas deve ser validado com duas gerações consecutivas, inspeção da configuração resultante e teste SMTP. Fonte consultada pelo responsável da auditoria em 2026-10-01: [cPanel — Exim Configuration Manager](https://docs.cpanel.net/whm/service-configuration/exim-configuration-manager/).

**Sobrevivência real a `/usr/local/cpanel/scripts/buildeximconf`: NÃO CONFIRMADA.** Não há prova de cPanel executando neste documento.

## Estágios SMTP e variáveis

| Estágio | Integração upstream observada | Dados disponíveis/usados |
|---|---|---|
| CONNECT | Nenhum snippet instalado para decisão SPFBL | IP é usado depois em RCPT |
| EHLO/HELO | Nenhuma chamada nesse estágio | `$sender_helo_name` é lido em MAIL/RCPT |
| MAIL FROM | Somente caminho ASFP/Perl | `$sender_host_address`, `$sender_helo_name`, `$sender_address`, `$sender_address_domain`, `$runrc`, `$value` |
| RCPT TO | `spfbl_end_recipient`, caminho principal | IP, MAIL FROM, HELO, `$local_part@$domain`, `$interface_port`, `$address_data`, `+local_domains`, `verify=recipient`, autenticação e IP recente autenticado |
| DATA/DKIM | `spfbl_begin_smtp_dkim`, `spfbl_begin_check_message_pre` | Headers From/Reply-To/Subject/Date/Message-ID/In-Reply-To/List-Unsubscribe; signers; Queue-ID; tamanho; malware; spam score |

Evidência: `client/spfbl_end_mail:1-23`; `client/spfbl_end_recipient:1-56`; `client/spfbl_begin_smtp_dkim:1-6`; `client/spfbl_begin_check_message_pre:1-96`.

RCPT consulta somente quando `$interface_port=25`. Antes da consulta, autenticação SMTP e `+recent_authed_mail_ips` podem `accept`; relay para domínio não local pode `drop` e enviar `ABUSE`. O snippet mantém relógio de sessão em `acl_c_begin_time`/`acl_c_session_time`, adia após 120 s e calcula existência do recipient. Receber em 465/587 não comprova esse mesmo fluxo. Evidência: `spfbl_end_recipient:1-43`.

`acl_c_spfbl`, `acl_c_spfbl_result`, `acl_c_spfblticket` e `acl_c_spfblticketset` são variáveis de conexão; acumulam tickets entre RCPTs. DATA move a lista para `_local` e limpa as variáveis. Aceites precoces em DATA ocorrem antes da limpeza em alguns caminhos. O comportamento com várias transações `MAIL` na mesma conexão, RSET e recipients com resultados diferentes precisa de teste; não assumir isolamento por mensagem. Evidência: `spfbl_end_recipient:44-56,132-136`; `spfbl_begin_check_message_pre:11-29`.

## Respostas e decisões atuais

A tabela completa, incluindo os 14 retornos exigidos no escopo, exits Bash/Perl, status extras, distinção `FAIL` com ticket e ações HAD, está em [PROTOCOL.md](PROTOCOL.md#qualificadores-e-ações).

Principais comportamentos: RCPT `GREYLIST`/`LISTED`/timeout/erro temporário resultam em `defer`; `FAIL` bare/`BLOCKED`/NXDOMAIN/erro permanente resultam em `deny`; `INVALID`/BANNED em `drop`; SPAMTRAP em `discard`. `FLAG`/HOLD acumulam ticket e continuam para DATA. Em DATA, FLAG coloca `X-Spam-Status: Yes`, WHITE coloca `No`, HOLD pode congelar a fila, e respostas HEADER indisponíveis também adiam. A entrega real à pasta Junk não é comprovada por esse header. Evidência: `spfbl_end_recipient:57-136`; `spfbl_begin_check_message_pre:41-96`.

O client upstream `RELEASE`/`REMOVE` executa `exim -Mt`/`exim -Mrm` e o cron HOLDING toma decisões de entrega/fila. Isso excede um adapter de classificação de envelope ou MONITOR e deve ficar fora da primeira integração HAD. Evidência: `client/spfbl.sh:3754-3773,3370-3498`.

## Fail-open, timeout e modo monitor

**Fail-open upstream: NÃO.** O Bash vazio retorna TIMEOUT (exit 9), RCPT adia para exit 9 e 20; HEADER adia para exit 2 e 4. `ERROR: FATAL` vira exit 7, rejeitado permanentemente no RCPT. O escopo exige que todas essas falhas continuem para Imunify/Rspamd. Evidência: `client/spfbl.sh:3686-3736,3216-3248`; `spfbl_end_recipient:65-68,124-131`; `spfbl_begin_check_message_pre:41-48`.

**Timeout HAD <=500 ms conexão/<=1 s total: NÃO implementado.** O Bash usa `ncat -w 3`; o Perl faz múltiplas consultas DNS e HTTP opcional com 5 s. Além da consulta envelope, DATA pode usar malware e SPAMC de 10 s e `spamd_address` com tmo 3 minutos. O limite de sessão 120 s não substitui deadline da consulta. Nenhuma evidência de P95 <200 ms foi obtida. Evidência: `client/spfbl.sh:79-83,3686`; `client/spfbl.pl:204-206,353-358`; `spfbl_begin_check_message_pre:3-9,63,79-80`; `spamfox.cpanel.sh:171-182`.

**O hook RCPT MONITOR está ativo na ACL cPanel de homologação; o hook DATA/HEADER novo ainda não foi instalado.** O protótipo valida o envelope e continua a ACL independentemente do estado SPFBL. O adapter systemd consulta o core nativo em `203.0.113.10:9877`; o túnel SSH anterior foi desativado após a migração para consulta direta. `exim -be` confirmou `CONTINUE|decision|LAN` pelo socket ativo; no Exim cPanel `4.100.1`, o hook RCPT passou `-bh` com quatro destinatários, MAIL nulo, RSET e socket ausente/timeout. Na configuração ativa, dois rebuild/reloads consecutivos passaram e o log registrou `CONTINUE|decision|LAN|27`.

A versão local do adapter e o novo snippet DATA enviam o comando upstream `HEADER` apenas quando há ticket validado. No Exim descartável 4.98.2, o smoke verificou tickets múltiplos, os campos de mensagem, ausência de ticket em uma mensagem sem resultado SPFBL e logs sem tokens. O core local respondeu `NOT FOUND` para ticket sintético inexistente. Ainda falta instalar o novo módulo e hook no cPanel 4.100.1, testar ticket real e observar mensagem SMTP/Imunify. O enforcement continua fora do adapter HAD.

Testes offline do Bash com transporte e Exim substituídos localmente: 47 casos, zero divergências, incluindo timeout, retorno fatal, desconhecidos e diferenças HEADER/QUERY. Isso é prova de tradução cliente, não prova de SMTP cPanel. Evidência: [notas e reprodução](evidence/client-protocol-test-notes.md), [resultado](evidence/client-protocol-results.txt).

## Compatibilidade com Imunify/Rspamd/SpamAssassin

**Preservação das camadas existentes pelo instalador upstream: NÃO.** Ele grava `acl_spam_scan_secondarymx=0`, `acl_outgoing_spam_scan=0`, `acl_outgoing_spam_scan_over_int=0`, `acl_default_exiscan=0`, `acl_default_spam_scan=0` e `acl_default_spam_scan_check=0`, além de substituir `spamd_address` com servidor SPFBL remoto. DATA contém `accept` cedo e classificação própria. Esses efeitos contradizem a exigência HAD de manter o fluxo vigente. Evidência: `client/spamfox.cpanel.sh:149-183,222-235`; `spfbl_begin_check_message_pre:11-20,71-96`.

A documentação oficial informa que Imunify Email utiliza Rspamd e integra-se mudando a configuração Exim; filtragem incoming é opt-in. Portanto a coexistência depende da configuração ativa, ordem das ACLs, hooks e enablement, não apenas da presença do pacote. Fonte consultada pelo responsável da auditoria em 2026-10-01: [Imunify — Email](https://docs.imunify360.com/email/).

A conclusão de código é que o instalador modifica componentes que precisam permanecer. **Quebra específica de Imunify na versão HAD: NÃO CONFIRMADA** sem comparar configuração real antes/depois e fluxo SMTP. O adapter HAD deverá acrescentar RCPT sem alterar `spamd_address`, opções SpamAssassin/Rspamd ou o serviço Imunify. WHITE/PASS/FLAG precisam chegar às próximas camadas. Um header não garante Junk sem verificar roteadores/filtros/Dovecot e a política de Rspamd.

## Rollback e atualização

`uninstall()` remove snippets e rotinas, aplica valores fixos a opções e apaga qualquer linha que contenha `timeout_frozen_after`, `spamd_address` ou `smtp_accept_max`; não restaura valores anteriores. Pode apagar configurações preexistentes e não oferece recuperação dos downloads sobrescritos. Não é rollback exato. `update()` repete downloads de master e mudanças de opções, reinicia sem validação prévia. Evidência: `spamfox.cpanel.sh:212-247,254-297`.

O manager HAD em `integrations/cpanel/manage_exim_acl.py` registra o hook e metadados, valida com `buildeximconf --acl_dry_run`, recompõe a configuração, testa sintaxe e executa sessão fake SMTP `-bh` exigindo resposta `LAN` antes de um reload opcional. Rollback/uninstall restauram o hook original e preservam alterações independentes no hook; o manager não edita `/etc/exim.conf` diretamente. Em 2026-10-02, `validate`, dois rebuilds/reloads consecutivos mantendo o hook, sessões `-bh` com resposta LAN e socket ausente e dois uninstalls reais anteriores passaram. O hook está ativo em MONITOR; a tentativa antiga com timeout está documentada e sua causa permanece sem confirmação. Consulte [evidência do ciclo real](evidence/cpanel-had-monitor-install-rollback-20261002.md). O próximo gate é acompanhar mensagens reais com o hook MONITOR e medir o fluxo do Imunify.

## Parsing e confiança nos scripts

| Risco/conclusão auditada | Evidência | Limite da prova |
|---|---|---|
| Script de firewall é recebido por TCP claro e executado como root | `firewall.cpanel.sh:9,11,47`; instalado em `spamfox.cpanel.sh:301-307` | Fluxo de execução confirmado; não houve interceptação de rede |
| Download de scripts/ACLs em branches mutáveis, escrita direta e ausência de verificação | `spamfox.cpanel.sh:67,77-78,139-147,215-220,304` | Risco de atualização/instalação confirmado por código |
| Contador global em `/tmp` modo 777, sem lock; retorno de 8 bits comparado a 256 | `spfbl.sh:43,49-75,3688-3694` | Fixtures confirmaram wrap; exploração de symlink não executada |
| Respostas de fila executam Exim com queue-id sem aspas/validação cliente | `spfbl.sh:3754-3773` | O core gera ID, mas transporte pode alterar; injeção de opções precisa validação isolada |
| Valores SMTP são interpolados em argumentos Exim e depois protocolo com aspas simples | `spfbl_end_recipient:50-54`; `spfbl.sh:3686`; `SPF.java:5517-5537` | Não afirmar shell injection apenas pela interpolação; Exim run/argv e SMTP parser precisam PoC |
| Sanitização de From/Subject é parcial; Message-ID/In-Reply-To/Date não têm a mesma sanitização | `spfbl_begin_check_message_pre:22-38` | Confusão de argumento/campo/injeção de CRLF precisa teste Exim e limites explícitos |
| Registro DKIM duplica a própria variável em vez de adicionar `$dkim_domain` | `spfbl_begin_smtp_dkim:4-5` | Erro da atribuição confirmado; impacto final de DKIM não validado em Exim |
| Cliente Perl assume IPv4 PTR com expansão de versão 6 e contém `break` em loops | `spfbl.pl:231-282` | Ramos suspeitos; execução com módulos/dados reais pendente |
| JSON HTTP é decodificado sem captura de exceção no bloco | `spfbl.pl:368-371` | Resposta malformada pode abortar o cliente; efeito SMTP depende do exit efetivo |
| Headers armazenados em variáveis de conexão e limpeza após aceites precoces | `spfbl_end_recipient:134-136`; `spfbl_begin_check_message_pre:11-29` | Contaminação entre transações não comprovada; teste obrigatório |

Dados SMTP e rede devem ser tratados como não confiáveis. O futuro adapter não deve usar shell para a conexão, deve limitar campos/resposta e distinguir falha de protocolo de decisão negativa. API key/mTLS são propostas futuras; o mecanismo CIDR existente pode identificar clientes, mas não representa sozinho barreira obrigatória de transporte.

## Matriz de homologação ainda necessária

| Critério | Evidência de sucesso exigida | Estado nesta auditoria |
|---|---|---|
| Consulta RCPT correta | `exim -bh`/SMTP com captura dos quatro campos e recipient válido/inválido | NÃO CONFIRMADO |
| PASS/WHITE/FLAG | Continuidade de ACL Imunify, headers e destino Inbox/Junk sem bypass | NÃO CONFIRMADO |
| GREYLIST/BLOCKED/FAIL/NXDOMAIN/INVALID/SPAMTRAP | SMTP 451/550/discard conforme política definida, sem simulação estreita | Mapeamento estático; SMTP NÃO CONFIRMADO |
| Serviço desligado/recusado/blackhole/resposta inválida/erro fatal | Exim aceita e Imunify permanece; deadline <=1 s | Socket ausente/timeout cobertos em testes do adapter e `-bh`; hook ativo em MONITOR; SMTP real ainda pendente |
| Múltiplos recipients/RSET/MAILs por conexão | Tickets e decisão isolados, sem estado residual | NÃO CONFIRMADO |
| MONITOR | Todas decisões registradas, nenhuma rejeição/adiamento/freeze por HAD | Hook ativo, dois rebuild/reloads e `-bh` confirmados; uma mensagem SMTP real e observação Imunify ainda pendentes |
| Persistência rebuild | Dois buildeximconf consecutivos com o hook instalado preservam o bloco e tráfego | PASS: duas execuções consecutivas de `install --reload` retornaram `installed` e `already-installed`; `healthcheck` confirmou hook e Exim gerado. Tráfego real segue pendente |
| Rollback exato | Arquivos/config e filtros equivalentes ao snapshot anterior | Ausente no upstream |
| Segurança de parsing | Apostrofes, espaços, campos grandes, CR/LF, NUL rejeitados/normalizados com continuidade | NÃO CONFIRMADO |
| Caso real `57.129.161.225`, `setor70f.ventaro.boats`, `secretaria42@setor70f.ventaro.boats` | Core/ação HAD pelo Exim ativo e comparação de conteúdo/entrega | Core respondeu `BLOCKED` em 392 ms; hook ficou `CONTINUE` em MONITOR. DNSBL retorna `127.0.0.3`. Nenhuma regra `.boats` foi criada e o ZIP local não contém IP/PTR/remetente ou `.boats`; motivo exato permanece incerto. Sem DATA, score SpamAssassin/Imunify e entrega Inbox/Junk seguem NÃO CONFIRMADOS. [Evidência](evidence/cpanel-boats-envelope-20261002.md) |
| 100/500/1000 consultas/s | P50/P95/P99, erros/timeouts, CPU/RAM e SMTP operacional | NÃO CONFIRMADO |

O adapter e o hook em `integrations/cpanel/` já estão instalados na homologação em modo MONITOR. A próxima etapa é correlacionar uma mensagem SMTP autorizada até a entrega e a classificação Imunify; enforcement pelo HAD permanece fora do estado validado. Os comandos de instalação upstream acima são objeto de auditoria, não instrução para implantação.
