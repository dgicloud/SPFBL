# Serviços externos e dependências SPFBL

Data: 2026-10-01. Baseline: `7b0232e96f16faca151340b80c418838a800237f`.

Inventário de literais e fluxos do código/configuração/scripts e, separadamente, de dados históricos do repositório. Nenhum serviço público foi consultado. Estado atual de DNS, autorização, quota, política de uso, certificados, contratos e TTL publicado pelos operadores são **NÃO CONFIRMADOS**. “Obrigatório” abaixo descreve a função do código, não obrigação contratual.

## Inventário completo dos nomes `*.spfbl.net` encontrados

| Host | Arquivo/evidência | Função | Obrigatório | Precisa autorização | Pode substituir |
|---|---|---|---|---|---|
| `matrix.spfbl.net` | `src/net/spfbl/core/Peer.java:1074-1093`; `core/Core.java:1625`; `client/spfblpostfix.pl:52`; `client/spfblquery.go:25`; `client/spfbl-qmail-spp.sh:42` | Seed/peer P2P programado, hostname de modo Matrix e destino de clientes de consulta | **NÃO** para core local/malha HAD; **SIM** para manter o destino literal desses clientes | Peering: aceite remoto **NÃO CONFIRMADO**. Clientes: scripts orientam liberação, ver abaixo | Cadastro de peers/clientes próprios permitido pelo código; não equivale à mesma inteligência pública |
| `matrix.spfbl.net` | `client/spamfox.cpanel.sh:79`; `spfbl.directadmin.sh:82` | HTTPS de assinaturas `spfbl.hsb`, `spfbl.ign2`, `cpanel.ign2` para ClamAV | Só para essas bases externas configuradas pelos instaladores | **NÃO CONFIRMADO**, sem credencial no download mostrado | Repositório próprio compatível; preservar origem enquanto seu uso estiver ativo |
| `matrix.spfbl.net` | `client/spfbl.spamcenter.sh:29,72` | HTTPS `/whatsmyip/` para descoberta do IP público | Só para o fluxo Spamcenter sem IP informado | **NÃO CONFIRMADO**; curl mostrado sem token | Serviço de IP próprio/configuração explícita, após validar o fluxo |
| `dnsbl.spfbl.net` | `client/spfbl.pl:470,486,488,505` | Consultas DNS A de reputação negativa de IP, FQDN/HELO e email | **SIM** no ramo público literal do cliente; **NÃO** como dependência universal do Java | **NÃO CONFIRMADO**; não há API key nas consultas A; aviso de limites em `spfbl.pl:4` | O core pode servir zona DNSBL própria, mas trocar o sufixo desse cliente requer adaptação/validação |
| `dnswl.spfbl.net` | `client/spfbl.pl:407,427,449` | Consultas DNS A de reputação positiva/categoria | Igual ao DNSBL | **NÃO CONFIRMADO**; nenhuma credencial no formato DNS observado | Zona própria compatível; dados/inteligência pública não são automaticamente copiados |
| `score.spfbl.net` | `client/spfbl.pl:524,537,550` | DNS A `127.0.1.N`, consultado quando houve sinal `$bad` em DNSBL | Condicional à classificação negativa no cliente; não é uma consulta P2P do core | **NÃO CONFIRMADO** | Zona SCORE própria é suportada pelo Java; adaptar cliente quando autorizado |
| `uribl.spfbl.net` | `client/uribl.pl:1191,1381` (mensagens `:1386-1481`) | Mail::RBL para assinaturas de URL, executável, hostname, IP/email no utilitário de conteúdo | Condicional ao uso desse utilitário; não é pré-requisito de P2P | **NÃO CONFIRMADO** | RHSBL própria; validar assinatura, caches e comportamento das chamadas Mail::RBL |
| `abuse.spfbl.net` | `src/net/spfbl/data/Abuse.java:201,236,253,282,342` | DNS A de inscrição/opt-out de abuso e TXT de contato por IP | Dependência hardcoded para esses métodos quando `Core.isMatrixDefence()` é falso; não impede iniciar o daemon | Sem token no código; inscrição do contato influencia a resposta; regras públicas **NÃO CONFIRMADAS** | Nenhuma opção de conf para mudar DNSAL encontrada; substituição real exigiria adaptação futura ou DNS controlado compatível |
| `dnsal.spfbl.net` | `src/net/spfbl/data/Abuse.java:381-408`, especialmente `:391` | TXT de contatos de abuso por zona/hostname/domínio | Condicional ao lookup de contato fora do modo Matrix | **NÃO CONFIRMADO** | Hardcoded; mesma ressalva do Abuse acima |
| `matrix._domainkey.spfbl.net` | `data/dkim.txt:190` | Registro histórico de chave pública DKIM carregado nos dados do baseline | **NÃO** como servidor central/seed; pode ser relevante para verificar assinatura Matrix | Consulta DKIM convencional não usa credencial; política pública **NÃO CONFIRMADA** | Não fazer troca de nome em registro histórico: mudaria a identidade assinante |
| `mx-br.spfbl.net` | `data/fqdn.txt:120672,365199` | Associação histórica de FQDN IPv6/IPv4 | **NÃO** como endpoint hardcoded de consulta | Não há admissão/token definido por esse registro | Não substituir dados de terceiros por hostname HAD; tratar como dado histórico |
| `mx-us.spfbl.net` | `data/fqdn.txt:126985,705995` | Associação histórica de FQDN IPv6/IPv4 | Igual ao registro anterior | Não definido por esse dado | Igual ao registro anterior |

Também aparece o domínio raiz `spfbl.net`: copyright/email de autor, links de ajuda/TOTP/feedback/contato e páginas informativas. Exemplos: `src/net/spfbl/service/ServerHTTP.java:1252,5393,6896`; `src/net/spfbl/data/Abuse.java:1032,1155`; `client/spamfox.cpanel.sh:205`; `client/spfbl.spamcenter.sh:60`; ACLs `client/spfbl_end_recipient:59-130`. Esses links são navegados pelo usuário/emitidos em mensagens, não um bootstrap P2P nem prova de autenticação externa. Manter avisos legais e atribuições.

O cliente Bash principal usa **IP literal `54.233.253.229`** (`client/spfbl.sh:36`) e não o hostname Matrix no destino ativo; os comentários `:22-24` referem Matrix. Não resolver ou identificar esse IP como Matrix atual sem verificação externa. `QUERY_TIMEOUT=10`, `MAX_TIMEOUT=256`, `PORTA_SERVIDOR=9877` e `PORTA_ADMIN=9875` são defaults desse cliente (`:37-43`), não a meta HAD de 1 s.

## Matrix: papéis distintos

### Peer/seed do core

`Peer.load` carrega `data/peer.map`. Só quando o arquivo inexiste e já há conexão P2P cria Matrix em 9877/9878/443, Receive.ACCEPT, Send.REPUTATION, versão 2.8, e envia HELO (`Peer.java:1022-1098`). No primeiro start real, `Core.main -> Server.loadCache -> Peer.load` precede criação de `peerUDP`, impedindo esse bootstrap (`Core.java:2731,2809`; `Server.java:140`). Portanto o literal seed não prova ingresso automático. Ver [SPFBL-P2P-AUDIT.md](SPFBL-P2P-AUDIT.md).

Matrix não é somente uma página web: existe como destino P2P UDP, destino de consulta cliente TCP e fornecedor HTTP de bases/IP. Não há consulta Matrix HTTP que retorne uma lista de peers no fluxo P2P observado. Como qualquer peer aceito, pode fornecer REPUTATION/BLOCK; não há classe separada de “reputação Matrix” no cálculo numérico.

Fallback da função P2P: sem peer conectado/aceito o core mantém dados locais e peers previamente persistidos; não troca automaticamente para `score.spfbl.net`. Na falha de chave AES, envio P2P faz fallback para UDP simples (`ServerP2P.java:492-513`), o que é fallback de transporte e não de reputação.

### Cliente de consulta

`spfblpostfix.pl` abre TCP Matrix:9877 (`:51-55`). `spfblquery.go` resolve Matrix (`:25`). Qmail usa Matrix literal (`spfbl-qmail-spp.sh:42`). Bash usa o IP acima. As instruções históricas nos clientes pedem liberação de consultas por `leandro@spfbl.net` (`client/spfbl.sh:22-24`, `spfblpostfix.pl:5-7`, `spfbl-qmail-spp.sh:22-24`); instaladores cPanel/DirectAdmin mostram falta de permissão e `https://spfbl.net/en/contact` (`spamfox.cpanel.sh:203-205`, `spfbl.directadmin.sh:165-167`).

Isso confirma a presença de um procedimento orientado no código para **clientes**. Responsável atual, canal vigente, valores requisitados, limite contratado e aprovação P2P pública são **NÃO CONFIRMADOS**. Não há API key Matrix hardcoded no protocolo UDP observado; não extrapolar essa ausência para permissão pública irrestrita.

### Bases ClamAV e descoberta de IP

Os instaladores adicionam URLs Matrix ao `additional_dbs` do clamav-unofficial-sigs. A cache, atualização e fallback efetivos pertencem também a esse programa externo, não apenas ao SPFBL; não foram executados aqui. Spamcenter usa `curl -s https://matrix.spfbl.net/whatsmyip/` sem timeout explícito nos trechos `:29,72`. Não chamar esses scripts para provar P2P: têm efeitos operacionais de instalação/conteúdo.

## Score: consulta e resposta

Fluxo do cliente `client/spfbl.pl`:

1. Avalia SPF e FQDN.
2. Se não existe `$query` de licença, consulta DNSWL e depois DNSBL.
3. Apenas se `$bad` é verdadeiro, consulta `<email>.score.spfbl.net`; sem score, tenta `<fqdn>.score.spfbl.net`; ainda sem resposta tenta `<ip-reverso>.score.spfbl.net` (`:521-562`).
4. Aceita somente `127.0.1.<1-3 dígitos>` como score (`:528-529`, `:541-542`, `:554-555`).
5. `$bad ge $score` leva a `reject`; ausência de score com `$bad` leva, salvo outras condições, a `junk` (`:582-590`). **`ge` é comparação textual Perl**, não `>=`; não atribuir a esse trecho uma fórmula numérica confiável sem correção e teste.

O Java pode **servir** SCORE numa zona configurada: `ServerDNS.Connection.run`, `src/net/spfbl/service/ServerDNS.java:1241-1253`, consulta `SPF.getSpamProbability(clientQuery, 32)` e calcula `100 - int(100*probabilidade)`; responde `127.0.1.N`, ou 100 para Ignore, ou resultado sem listagem. Existem ramos equivalentes para IPv6 (`:1424-1436`) e hostname/email (`:1668-1680`). Isso documenta a semântica do servidor auditado, não prova que a instância pública atual roda esse mesmo commit.

Não há cache de SCORE dedicada no script. Resolução/cache de DNS externa pertence ao Net::DNS/resolver; o script não persiste score e não aplica TTL explicitamente. Quotas, autenticação do serviço público e TTL atual são **NÃO CONFIRMADOS**.

## DNSBL: consultas, respostas e indisponibilidade

`spfbl.pl` cria resolver com `8.8.8.8` e `208.67.222.222` (`:200-202`), normaliza IPv4 reverso ou IPv6 em nibbles (`:211-289`), e consulta A para IP/FQDN/HELO/email nos sufixos SPFBL.

| Código reconhecido pelo cliente | IP (`:470-483`) | FQDN/HELO (`:484-503`) | Email (`:504-518`) |
|---|---|---|---|
| `127.0.0.2` | Incrementa bad | Incrementa bad | Incrementa bad |
| `127.0.0.3` | Incrementa suspicious | Incrementa suspicious | Incrementa suspicious |
| `127.0.0.4` | Incrementa notserver | Marca residential | Marca generic |
| Outros | Ignorados nesses ramos | Ignorados | Ignorados |

O servidor local também emite `127.0.0.5` no ramo IPv4 para faixa de abuso indesejável (`ServerDNS.java:1166-1169`); o cliente Perl auditado não trata esse código nos ramos acima. Não afirmar que servidor e cliente conhecem exatamente a mesma taxonomia.

As consultas estão em `eval`; packet ausente e erros não acrescentam os sinais daquela consulta. Não há distinção explícita entre NXDOMAIN, SERVFAIL, timeout e bloqueio por quota nesses ramos; todos podem acabar sem sinal. Isso é perda de evidência, não uma garantia global de fail-open: outras condições SPF/FQDN ainda podem rejeitar/adiar a mensagem (`spfbl.pl:570-654`).

O script não define `udp_timeout`, `tcp_timeout`, retry DNS ou um prazo agregado. Esses valores de runtime dependem das versões Net::DNS/Mail::SPF instaladas e são **NÃO CONFIRMADOS**. Os timeouts DNS Java de 1000 ms/retry 1 (`Server.java:1626-1627`) não se aplicam automaticamente ao Perl. Várias consultas sequenciais também podem superar 1 s.

TTL/cache: nenhuma persistência DNSBL específica no Perl e nenhuma leitura de `rr->ttl` nesse fluxo. Caching recursivo segue o resolver externo. O servidor local define TTL por resultado: exemplos IPv4 5 dias (BLOCK+RED), 3 dias (BLOCK+YELLOW), 1 dia (suspicious/RED) e 1 hora (NXDOMAIN sem listagem), `ServerDNS.java:1125-1179`. Esses TTL **não foram medidos no DNSBL público**.

## DNSWL: confiança e prioridade

| Código | Categoria no cliente | Influência demonstrada |
|---|---|---|
| `127.0.0.2` | good | Aceita por good antes de NXDOMAIN/residential e evita ramo DNSBL (`spfbl.pl:447,467,567-569`). |
| `127.0.0.3` | essential | Pode transformar SPF não-pass em accept (`:591-593`). |
| `127.0.0.4` | transactional | Pode transformar SPF não-pass em accept (`:594-596`). |
| `127.0.0.5` | bulk | Aceita bounce; fail vira softfail; permerror vira accept (`:564-566,597-602`). |
| `127.0.0.6` | trusted | Aceita na posição posterior da árvore de decisão (`:621-623`); não vence todas as condições anteriores. |

Consulta IP/FQDN quando o remetente não é `$focused = freemail && SPF pass` (`:398,405-445`); consulta email se ainda não good e SPF pass (`:447-459`). Falhas não marcam categoria; não há token, timeout DNS explícito, TTL/cache persistente ou distinção de SERVFAIL/NXDOMAIN nesse caminho. Não há multiplicação de score P2P pela resposta DNSWL neste script; trata-se de classificação/prioridade de decisão.

No servidor Java local, IPv4 DNSWL exige status GREEN e ausência de Block. Ignore, White, Provider, CIDR e Abuse determinam os códigos e TTL (`ServerDNS.java:1190-1240`); por exemplo Ignore tem 5 dias e White 1 dia. A instância pública atual e seu TTL real seguem **NÃO CONFIRMADOS**.

## Abuse e DNSAL: dependência funcional frequentemente esquecida

Em um hostname HAD, `Core.isMatrixDefence()` é falso (`Core.java:1622-1629`). A classe `Abuse` então consulta:

- `<email>.abuse.spfbl.net A`: `127.0.0.2` significa subscribed; `127.0.0.3` significa unsubscribed (`Abuse.isSubscribed():227-241`, `isUnsubscribed():244-259`). Falha retorna false para subscribed e true para unsubscribed.
- `<ip-reverso>.abuse.spfbl.net TXT`: busca contatos para IPv4/IPv6 (`Abuse.java:279-299,339-358`). Sem TXT, retorna null; tenta preferir contato inscrito.
- `<hostname-ou-domínio>.dnsal.spfbl.net TXT`: busca contatos por zona (`getEmailZone():381-408`), também preferindo inscrição.

`Reverse.getAddress4` e `Reverse.getTXTSet` usam `Server.getAttributesDNS` (`Reverse.java:612-633,906-927`). O retorno externo não tem cache local dedicado implementado nesses métodos; são usados contextos JNDI reaproveitados, e caches de resolução podem existir na infraestrutura. A cache local de Abuse não equivale a espelhar automaticamente as bases DNSAL públicas.

São chamadas funcionais além do P2P; elas podem afetar contato de abuso, inscrição, default de reputação de abuso e categoria DNSWL (`Abuse.java:1377-1385,1603`; `ServerDNS.java:1232-1235`). A indisponibilidade é tratada conservadoramente nesses métodos, mas não foi medido o impacto agregado de latência ou perda de classificação. Não há `dnsal_host` em `run/spfbl.conf` nem setter de domínio nesse fluxo. Operação totalmente independente de SPFBL público exige decidir esses comportamentos numa etapa futura; não basta retirar o peer Matrix.

## Licença HTTP do cliente Perl e fallbacks

O modo **`header`** com quarto argumento `header` lê `/etc/spfbl.conf`, parâmetro `licence`, e constrói URL de consulta (`spfbl.pl:169-193`). O modo Postfix stdin não passa por esse ramo. O destino é variável, portanto não há hostname fixo que possa ser inventariado apenas por `*.spfbl.net`.

A consulta HTTP inclui IP, HELO, sender, parâmetros adicionais, resultado SPF e FQDN; usa verificação de hostname TLS, cookie jar `/var/spfbl/cookie.jar`, timeout 5 s e JSON com `result`/`information` (`:352-371`).

- HTTP 429 remove licença e esvazia query, acionando ramo público DNS (`:372-375`).
- Falha HTTP 500 com “Connection refused” esvazia query e aciona DNS (`:376-378`).
- Connection timed out / Can't connect / read timeout e demais erros mantêm query e definem temperror (`:379-394`), portanto **não** acionam o fallback de listas nessa execução.

Esse fluxo não é o ticket UDP P2P. O destino real, licença vigente, autorização e política de query só podem ser confirmados pela configuração de runtime e operador; não foram fornecidos/consultados.

## Outras dependências externas observadas

Não são nomes `*.spfbl.net`, mas precisam entrar no mapa de egress da instalação:

| Serviço | Evidência | Papel/condição |
|---|---|---|
| Resolver DNS primário/secundário/SO | `run/spfbl.conf:32-34`; `Server.java:1620-1685`; Perl `spfbl.pl:200-202` | Identidade, SPF/PTR/MX/DKIM e listas; core permite configuração, Perl fixa dois resolvedores no trecho auditado. |
| ACME/certificados | `run/spfbl.conf:84-93`; `Core.java:3558-3579` | Automação opcional; HTTP:80 e email admin; não presume transporte P2PS funcional. |
| Google reCAPTCHA | `run/spfbl.conf:125-128`; `ServerP2P.java:80-85` | Configuração opcional para web; o caminho P2PS também o exige. |
| Google Safe Browsing | `run/spfbl.conf:130-132`; `Core.java:4522` | API de conteúdo/URLs, depende de chave configurada. |
| PayPal | `ServerHTTP.java:1483,1610,3952`; `:1648,4041,4057` | Fluxos de pagamento/licença web existentes; não pré-requisito de malha HAD. |
| GitHub raw e utilitários de instalação | `client/spamfox.cpanel.sh:67`; `run/install.sh`; `run/spfbl-update.sh` | Downloads de clientes/build/configuração; manter versão e hash sob controle antes de implantação. |
| WHOIS brasileiro | `run/spfbl.conf:41-45` | Default de exemplo NONE desativa; consultas WHOIS e outros lookups dependem da função exercida. |
| SMTP e URLs de mensagens | `run/spfbl.conf:66-82`; `src/net/spfbl/data/URI.java:254,310` | Relatórios/envio e análise de links de terceiros; destinos variáveis exigem inventário de runtime. |

Esta tabela auxiliar não afirma que esses serviços foram ativados nem auditados operacionalmente; registra os pontos relevantes encontrados além da família SPFBL.

## O que precisa permanecer e como validar substituição

Durante esta etapa preservar todos os literais, dados históricos e algoritmos. Para a operação futura, “precisa permanecer” depende do caminho realmente escolhido:

- **Malha HAD local:** peer Matrix não é obrigatório. As tabelas de peers e reputação local continuam; nenhuma resposta SCORE/DNSBL pública é consultada automaticamente para compensar falta de peer.
- **Perl com listas públicas:** preservar DNSBL, DNSWL e SCORE até existir implementação e prova equivalentes. O timeout agregado e os resultados quando DNS falha precisam de teste antes de chamar esse modo fail-open.
- **Utilitário URIBL/ClamAV:** preservar bases Matrix e URIBL enquanto esse fluxo estiver instalado; seu escopo é conteúdo, diferente da decisão SMTP central desejada.
- **Core HAD com Abuse:** ainda pode usar abuse.spfbl.net/dnsal.spfbl.net mesmo sem Matrix P2P. Uma futura decisão de privacidade/autonomia deve cobrir os lookups, os relatórios e sua influência na classificação.
- **Links informativos e dados de identidade de terceiros:** não substituir cegamente por domínio HAD; revisar UI depois da auditoria, preservando copyright/licença e identidade técnica de DKIM/FQDN.

Para prova operacional em staging autorizado: registrar cada consulta/egress, testar resposta válida, NXDOMAIN, SERVFAIL, timeout, quota/REFUSED e indisponibilidade; medir latência agregada; testar cache e TTL sem inferir que defaults públicos estão iguais ao código local. Acesso público só após escopo e procedimento de admissão confirmados.

## Reprodução do inventário e fronteira de evidência

```powershell
rg -n -i 'matrix\.spfbl\.net|score\.spfbl\.net|dnsbl\.spfbl\.net|dnswl\.spfbl\.net|abuse\.spfbl\.net|dnsal\.spfbl\.net|uribl\.spfbl\.net' src run client
rg -N --no-filename -i -o '(?:[a-z0-9_-]+\.)+spfbl\.net' --glob '!docs/**' --glob '!HAD-AntiSpam-Escopo-Completo.md' --glob '!lib/**' . | Sort-Object -Unique
rg -n -i '(mx-br|mx-us|matrix\._domainkey)\.spfbl\.net' data
```

Foram identificados **sete nomes de serviços** no código/script e **três nomes adicionais em dados históricos**, mais o domínio raiz informativo. Literal ausente não exclui destinos compostos por configuração, DNS, licença, email ou URL da mensagem. Não houve captura de tráfego nem consulta pública: disponibilidade, permissão real, quotas, políticas, TTL externo e substituição equivalente permanecem **NÃO CONFIRMADOS**.
