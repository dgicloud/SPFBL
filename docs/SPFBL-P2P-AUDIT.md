# Auditoria P2P do SPFBL

Data: 2026-10-01. Baseline auditado: `7b0232e96f16faca151340b80c418838a800237f`.

Este relatório rastreia o código local. Nenhum pacote foi enviado à rede pública SPFBL, nenhuma autorização externa foi solicitada e o core foi preservado. As conclusões de fluxo abaixo são estáticas; a disponibilidade, os critérios operacionais e a admissão atual da rede pública são **NÃO CONFIRMADOS**.

## Respostas às perguntas de decisão

| Pergunta | Resposta | Evidência e limite |
|---|---|---|
| Um primeiro start original de `antispam01.exemplo.com` entra automaticamente na rede existente? | **NÃO** | `Core.main`, `src/net/spfbl/core/Core.java:2728-2731`, carrega os caches antes de construir `peerUDP` em `:2809`. `Server.loadCache`, `src/net/spfbl/core/Server.java:140`, chama `Peer.load`. O bootstrap em `src/net/spfbl/core/Peer.java:1086-1094` exige `Core.hasPeerConnection()`, que retorna falso quando `peerUDP == null` (`Core.java:249-254`). Além disso `run/spfbl.conf:38` deixa `hostname` comentado. |
| Podemos consumir reputação P2P pública sem trocar o algoritmo? | **PARCIAL** | Existe cadastro manual, recepção e combinação de tabelas; o uso efetivo depende de cadastro e aceitação pelo outro operador, DNS/IP compatíveis e correlação com dados locais. Não houve confirmação da aceitação pública. |
| Precisa autorização? | **SIM**, no mecanismo técnico para utilizar dados recebidos; procedimento público **NÃO CONFIRMADO** | HELO desconhecido cria peer com `Receive.DROP` (`Peer.java:77-78`, `ServerP2P.java:356-367`). `PEER ADD` administrativo muda para ACCEPT (`AdministrationTCP.java:3264-3270`); `PEER SET` muda políticas (`:3302-3329`). Criar peer automaticamente não significa confiar nele. |
| Como um peer entra? | **PARCIAL**: manualmente ou por HELO válido, seguido de autorização local | Sem descoberta de listas via DNS, gossip de peers ou Matrix HTTP no fluxo observado. Há bootstrap Matrix programado, mas ineficaz no primeiro start devido à ordem acima. |
| Rede HAD independente da pública? | **SIM**, como malha lógica de nós cadastrados com IPs não reservados; **PARCIAL** para rede de transporte RFC1918/ULA | Não há exigência de peer Matrix para cadastro/troca privada. HELO rejeita IP reservado em `FQDN.addFQDN`, `src/net/spfbl/data/FQDN.java:395-396`; 10/8, 172.16/12, 192.168/16 e fc00::/7 estão na classificação reservada. Validação operacional da malha HAD ainda é **NÃO CONFIRMADA**. |
| HAD privada + SPFBL pública? | **PARCIAL** | O mesmo MAP aceita peers de vários domínios. Porém não há namespaces HAD_LOCAL/SPFBL_PUBLIC nem ponte automática de reputação recebida; BLOCK REPASS pode propagar entre os grupos. A participação pública segue não confirmada. |
| Todos os peers têm o mesmo peso? | **NÃO** | `reputationMax = max(256 × correlação, 0)`, `Peer.refreshReputationMax():1287-1289`, `Core.getReputationLimit():2325-2328`; cálculo da correlação em `Peer.getCorrelacao():230-268`. |
| Um peer autorizado pode enviar reputação falsa? | **SIM**, há superfície técnica; impacto final depende do peso | `Peer.setReputation():1214-1275` recebe contadores fornecidos pelo peer. Existe filtro de token e correlação, mas não prova externa dos eventos nem assinatura de feedback. Não foi executado ataque na rede. |

Não confundir a autorização de **clientes SMTP** com a autorização de **peers P2P**. Os comentários `client/spfbl.sh:22-24` orientam liberar consultas Matrix por `leandro@spfbl.net`; isso documenta um fluxo de cliente, não comprova o processo administrativo atual para ingresso na rede pública P2P.

## Inventário dos arquivos relevantes

| Arquivo | Classe/componente | Papel rastreado |
|---|---|---|
| `src/net/spfbl/core/Core.java` | Core | Configuração, portas, hostname, construção de ServerP2P, métodos de envio e limite reputacional. |
| `src/net/spfbl/core/Server.java` | Server | Ordem de load/store, DNS auxiliar, desligamento e persistência. |
| `src/net/spfbl/core/Peer.java` | Peer / Peer.Binomial | Cadastro, políticas, tabelas por peer, HELO, AES/HTTPS, envio, correlação, expiração e `peer.map`. |
| `src/net/spfbl/service/ServerP2P.java` | ServerP2P / Connection | UDP simples/cifrado, parsing de HELO/REPUTATION/BLOCK, pool e tamanho. |
| `src/net/spfbl/core/AdministrationTCP.java` | AdministrationTCP | `PEER ADD`, `DROP`, `SHOW`, `SET`, `PING`, `STORE`; regras de firewall geradas. |
| `src/net/spfbl/service/ServerHTTP.java` | ServerHTTP | Endpoint HTTPS `/.well-known/secret-key/<hostname>`. |
| `src/net/spfbl/data/FQDN.java` | FQDN | Associação IP/hostname e validação DNS para HELO/identificação. |
| `src/net/spfbl/core/Reverse.java` | Reverse | Consultas A/AAAA usadas pela validação. |
| `src/net/spfbl/whois/Subnet.java`, `SubnetIPv4.java`, `SubnetIPv6.java` | Subnet | Normalização e classificação de endereços reservados. |
| `src/net/spfbl/spf/SPF.java` | SPF.Distribution | Broadcast de contadores locais; soma local+peer nas consultas de probabilidade. |
| `src/net/spfbl/data/Block.java` | Block | Emissões BLOCK e lista global onde BLOCK recebido é importado. |
| `src/net/spfbl/core/Analise.java`, `core/User.java`, `service/ServerSPFBL.java` | Analise / User / ServerSPFBL | Outros produtores de BLOCK (`Analise.java:1056`, `User.java:5060`, `ServerSPFBL.java:1096`). |
| `src/net/spfbl/data/Ignore.java`, `Provider.java`, `Reputation.java`, `Generic.java` | Listas/reputação | Proteções aplicadas no recebimento de BLOCK e REPUTATION. |
| `run/spfbl.conf` | Configuração | `hostname`, `spfbl_port`, `spfbls_port`, `peer_limit`, `udp_max`, HTTPS e reCAPTCHA. |
| `client/spfbl.sh` | CLI Bash | Interface administrativa peer (`:2187-2462`). O subcomando documentado `peer send` não encontra ramo equivalente PEER SEND no servidor (`AdministrationTCP.java:3246-3343`). |

## Descoberta, bootstrap e admissão

Fluxo de primeiro start verificado no código:

```text
Core.main
  loadConfiguration
  Server.loadCache
    Peer.load
      peer.map existe -> desserializa peers
      peer.map ausente -> só criaria Matrix se Core.hasPeerConnection
                          neste momento peerUDP ainda é null
  inicia ADMIN / DNS / HTTP / consulta SPFBL
  se hostname válido e spfbl_port > 0 -> cria ServerP2P
```

O repositório auditado não contém `data/peer.map`. Um arquivo existente é carregado em vez de acionar bootstrap (`Peer.java:1024-1086`); arquivo existente inválido registra erro e não cai no ramo Matrix. Não há segundo `Peer.load()` no fluxo de main.

O bootstrap programado é exatamente `Peer.create("matrix.spfbl.net", 9877, 9878, 443)`, `Receive.ACCEPT`, `Send.REPUTATION`, versão `2.8`, HELO (`Peer.java:1089-1093`). É uma intenção explícita no código, não evidência de ingresso automático no processo real.

O cadastro manual é `PEER ADD hostname:porta[:porta-cifrada[:https]] [email]`; cria o objeto e autoriza ACCEPT. HELO chega via UDP, inclui conexão, versão opcional e email opcional, valida sintaxe e `FQDN.addFQDN(IP-origem, hostname, true)`, e cria ou atualiza o peer (`ServerP2P.Connection.run():328-392`). Novo cadastro por HELO conserva `DROP`; cadastro existente pode manter permissões e chaves ao trocar hostname pelo ramo clone (`:377-381`, `Peer.clone():537-550`).

`FQDN.addFQDN` exige hostname, IP não reservado, hostname não genérico e A/AAAA que contenha o IP de origem (`FQDN.java:384-424`). Não exige, nesse ramo, uma consulta PTR coincidente. `Peer.get(InetAddress)` procura peer cujo nome coincide com a associação FQDN daquele IP (`Peer.java:700-708`, `FQDN.isFQDN():182-189`). É identidade baseada em IP/DNS/cache; o endereço e a porta UDP de origem não constituem token secreto.

## Portas, bind, timeout, retry e liveness

| Serviço | Default/exemplo | Protocolo e evidência |
|---|---|---|
| P2P básico | 9877 | UDP; usa o mesmo número de `spfbl_port` que a consulta SPFBL TCP. `Core.java:2797-2810`, `ServerP2P.java:63-74`. |
| Consulta de cliente SPFBL | 9877 | TCP, separado do P2P apesar do mesmo número; `Core.java:2799`. |
| P2P cifrado planejado | 9878 | UDP AES, `spfbls_port`; código de bind `ServerP2P.java:87-97`. **Não presumir listener funcional**, ver ressalva abaixo. |
| Distribuição de chaves | 443 ou `https_port` | HTTPS, `Peer.requestSecretKey():312-368`, `ServerHTTP.java:2985-3020`. |
| Administração | 9875 | TCP `admin_port` (`run/spfbl.conf:50`); manter restrito à administração, não abrir aos peers. |
| DNS auxiliar | resolver configurado / SO | A/AAAA para identidade; `Reverse.java:578-658`, `Server.getAttributesDNS():1620-1628`. |

`new DatagramSocket(port)` não recebe endereço bind (`ServerP2P.java:73`, `:89`): o listener usa todas as interfaces disponíveis ao socket. `interface=eth0` não é aplicado por esse construtor. Firewall externo é parte necessária do isolamento.

O recebimento usa buffers de 1024 bytes (`ServerP2P.java:112`, `:151`); o envio usa `udp_max`, default 512 (`run/spfbl.conf:103-104`, `ServerP2P.send():515-523`). Não há timeout de resposta, ACK, número de sequência, retransmissão por mensagem ou confirmação de entrega. `send()` retorna o hostname após `SERVER.send`, ou UNKNOWN/UNREACHABLE/TOO BIG, não o resultado de processamento remoto (`ServerP2P.java:483-530`). `PEER PING` apenas chama `sendHELO`, portanto `HELO SENT` também não prova aceitação (`AdministrationTCP.java:3331-3339`).

HTTPS de chaves limita connect a 3000 ms e read a 5000 ms (`Peer.java:336-337`). DNS Java usa initial 1000 ms e retries 1 (`Server.java:1626-1627`); esses valores não são um teto agregado do processamento P2P. Peer sem recebimento por sete dias expira (`Peer.java:1278-1280`); contadores sem alteração por três dias expiram no maintenance (`:1308`, `:1450-1452`). Estatística de intervalo é observabilidade (`Peer.addNotification():1158-1166`), não rate limit por peer.

**Defeito de sequência a validar antes de usar P2PS:** `ServerP2P.run():79` executa `startService()` de forma síncrona; este método fica no loop `while (continueListenning())` com `SERVER.receive()` (`:107-138`). A criação de `SERVERS` só aparece depois desse retorno em `run():80-104`. Em funcionamento normal o primeiro loop não termina, portanto o socket cifrado não é criado. Além disso o caminho exige reCAPTCHA e HTTPS. A existência de `spfbls_port=9878` ou de código AES não prova transporte cifrado ativo.

## Payload realmente compartilhado

| Mensagem | Conteúdo | Limites |
|---|---|---|
| `HELO hostname:port[:ports[:https]] [version] [email]` | Endereço/portas, versão e contato do operador | Enviado sem cifra (`Peer.sendHELO():851-875`). Não transporta lista de peers. |
| `REPUTATION token ham spam [frequencyXi frequencyXi2]` | Snapshot de contadores HAM/SPAM e momentos opcionais de frequência | `Peer.sendToAll():793-848`; emitido apenas quando `spam % 3 == 0`; formato longo reduz para curto se exceder UDP_MAX. |
| `BLOCK token` | Token de blocklist de hostname/domínio/remetente | `Peer.sendBlockToAll():758-783`, `Peer.isValidBlock():939-953`. IP puro é recusado como BLOCK P2P. |
| Versão compacta cifrada | Remove prefixo REPUTATION/BLOCK antes de AES | `ServerP2P.send():498-509`; parser também aceita formas sem prefixo (`:414-432`). |

Não há mensagens específicas de whitelist, ticket, corpo, anexo, credencial SMTP, evento spamtrap completo ou ASN no parser P2P (`ServerP2P.java:328-437`). Eventos locais de feedback/spamtrap podem gerar novos contadores ou BLOCK, mas não são transmitidos como objetos desses tipos. Reputação IP/hostname/remetente só é compartilhada se o token é aceito por `SPF.isValidReputation` e chega à chamada sendToAll. A fórmula recebida é `spam/(ham+spam)`, zero quando sem amostras (`Peer.Binomial.getSpamProbability():1462-1467`).

## Políticas e confiança: comentários versus implementação

Políticas de envio declaradas: NEVER, REPUTATION, ALWAYS, REPASS, MIRROR; DUNNO e BLOCK são obsoletas (`Peer.java:123-131`, `:450-456`). Políticas de recebimento válidas incluem ACCEPT, REJECT, DROP, REPUTATION, REPASS e MIRROR (`:133-142`, `:473-485`).

**As descrições das enumerações não bastam para configurar isolamento:**

- `getSendAllSet` inclui **Send.REPUTATION** (`Peer.java:598-610`), e `sendBlockToAll` usa esse conjunto (`:766`). Logo REPUTATION também pode enviar BLOCK. ALWAYS e REPASS enviam reputação; MIRROR está em `getReputationSet`, mas fora do conjunto usado para HELO periódico/BLOCK.
- `processBlock` só nega por política **Receive.REJECT** e **Receive.DROP** (`Peer.java:977-980`). **Receive.REPUTATION aceita BLOCK**, assim como ACCEPT/MIRROR/REPASS, se passam os outros filtros. Não há política efetiva “somente reputação recebida” nesse método.
- BLOCK normaliza token, recusa IP puro, Ignore/Provider, duplicata e token local desejável; então `Block.addExact` insere na lista global (`Peer.java:967-995`). REPASS repassa para outros; mesmo ACCEPT pode encaminhar para destinos Send.REPASS via `sendToRepass`.
- REPUTATION recusa token inválido/genérico/TLD oficial/IP reservado e peers REJECT/DROP; contadores negativos são inválidos (`Peer.java:1222-1236`, `:1410-1420`). Zero/zero remove entrada; os demais substituem o snapshot por peer. Não há cap de contador recebido nesse setter, assinatura de evento nem verificação da alegação do peer.

O peso numérico não é uma trust list administrativa. A correlação Pearson compara probabilidade local e remota para tokens em comum, cada distribuição com mais de sete amostras; exige mais de 32 tokens (`Peer.getCorrelacao():236-267`). O cap é `max(256*correlação, 0)`, recalculado em `Peer.store -> dropExpired -> refreshReputationMax` (`:1002-1004`, `:1303`). Peer recém-criado começa com cap zero (`:97`), podendo não influenciar o cálculo numérico até existir base local suficiente e manutenção.

`SPF.Distribution.getSpamProbability(token, limit)` soma contadores locais e, para cada peer com cap >0, reduz proporcionalmente seus contadores ao cap; depois soma as contribuições (`SPF.java:7617-7637`). `getBinomial(token)` faz a mesma combinação (`:7755-7779`). Não há cap global somado de todos os peers. O envio `Distribution.getBinomial()` **sem token** usa apenas os conjuntos locais (`:7748-7752`), portanto reputação recebida da pública não é automaticamente rebroadcast como reputação pública para peers HAD. BLOCK repassado, ao contrário, perde proveniência explícita no payload.

## Autenticação e riscos de abuso observados

| Tema | Proteção encontrada | Limitação/risco verificável estaticamente |
|---|---|---|
| Peer desconhecido | HELO precisa DNS forward/IP compatível; default DROP | Um remetente com DNS válido pode criar cadastro, mas não fica automaticamente confiável. Não há limite de tamanho do MAP de peers em `Peer.create():566-576`; `peer_limit` limita workers, não quantidade de identidades. |
| UDP spoofing | Associação IP -> FQDN -> peer | Transporte simples não tem MAC, assinatura, challenge ou segredo; capacidade de spoof depende da rede. Não foi demonstrada exploração. |
| Canal cifrado | AES, chave via HTTPS com verificação de IP e principal de certificado `CN=<hostname>` | `Cipher.getInstance("AES")` não especifica modo/AEAD (`ServerP2P.java:314`, `:506`). Não há MAC/nonce aplicado no protocolo; criação do listener tem defeito de sequência; falha/ausência de chave faz fallback explícito para UDP simples (`:492-513`). |
| Chaves | KeyStore local, HTTPS, peer conhecido e origem compatível | Endpoint só exclui DROP, não REJECT (`ServerHTTP.java:2997`); chaves são registradas em TRACE (`Peer.java:303`, `:352`) e persistidas em peer.map. Restringir acesso a logs/backups. |
| Replay | Snapshot por peer evita soma aditiva de repetição idêntica | Sem timestamp remoto, sequência ou idempotência de evento: snapshot antigo pode substituir snapshot novo (`Peer.setReputation():1259-1269`). Repetição atualiza atividade de peer antes da validação (`ServerP2P.java:402`, `:412`). |
| Poisoning | Filtros de token, cap por correlação, Ignore/Provider e reputação local para BLOCK | Peer confiável pode alterar contadores alegados e importar BLOCK global. A proteção numérica não governa o fluxo BLOCK. Contadores são inteiros sem limite superior aplicado no setter; somas merecem validação de overflow. |
| Sybil | Novos peers ficam DROP; correlação requer histórico comum | Não há identidade organizacional, limite agregado por grupo ou peso total máximo. Vários peers autorizados com histórico correlacionado têm caps independentes. |
| Flood | Pool máximo de conexões e buffers pequenos | Não há rate limit por peer no handler observado; DNS/HTTPS podem ocupar worker. `peer_limit=16` não é uma defesa de volume por identidade. |
| Spamtrap/feedback falso | Eventos crus não estão no parser | Contadores falsos podem representar eventos inexistentes; não há prova do evento recebido. |
| Repass BLOCK | Filtro de duplicata evita reinserção repetida | Não há TTL/hop count ou namespace de proveniência no payload; REPASS conecta os grupos lógico privado e público. |

Esses pontos são riscos de desenho e fluxo, não um laudo de exploração pública. Testes adversariais em staging isolado, validação de alcance e severidade permanecem pendentes.

## Configuração reproduzível de malha HAD sem mudar o core

A malha lógica privada é viável com três hostnames próprios que resolvam para IPs roteáveis reais dos nós. DNS e o endereço de origem efetivo precisam concordar. Não usar endereços de documentação 192.0.2/24, 198.51.100/24 ou 203.0.113/24 para um teste de HELO real: também são reservados. RFC1918, CGNAT, loopback, IPv6 ULA e NAT que anuncie endereço diferente têm restrições no código acima.

Exemplo de `/etc/spfbl/spfbl.conf` do node01, mantendo o restante da configuração original:

```ini
hostname=antispam01.exemplo.com
admin_port=9875
spfbl_port=9877
peer_limit=16
udp_max=512
admin_email=antispam-ops@exemplo.com
```

Replicar com hostname próprio nos node02/node03. Abrir UDP 9877 exclusivamente entre os três IPs HAD. Manter TCP 9875 administrativo em loopback/rede de administração; TCP 9877 só para os MTAs autorizados. A porta UDP não é bindada apenas à interface de administração. HTTPS/AES é um recurso separado pendente de correção/verificação, não pré-requisito para a malha básica.

Após iniciar cada serviço em laboratório autorizado, enviar pela administração local no node01:

```sh
printf '%s\n' 'PEER ADD antispam02.exemplo.com:9877 antispam-ops@exemplo.com' | ncat -w 3 127.0.0.1 9875
printf '%s\n' 'PEER ADD antispam03.exemplo.com:9877 antispam-ops@exemplo.com' | ncat -w 3 127.0.0.1 9875
printf '%s\n' 'PEER SHOW' | ncat -w 3 127.0.0.1 9875
printf '%s\n' 'STORE' | ncat -w 3 127.0.0.1 9875
```

No node02, cadastrar node01 e node03; no node03, cadastrar node01 e node02. Cadastrar ambos os sentidos é necessário porque HELO recebido sozinho produz DROP. Para compartilhar blocklist em todos os sentidos, política Send.ALWAYS/Receive.ACCEPT pode ser definida por `PEER SET <hostname> ALWAYS ACCEPT`; considerar os riscos de importação global antes de usar. Não tratar REPUTATION como isolamento de blocklist neste baseline.

Inspecionar `PEER SHOW` e `data/peer.map` após STORE. Se aparecer `matrix.spfbl.net` em uma instalação reaproveitada, removê-lo individualmente com `PEER DROP matrix.spfbl.net` **nessa instalação HAD dedicada**, depois STORE. Não reutilizar `peer.map` público sem revisar todos os peers. A mudança é de configuração/dados de laboratório, não alteração do core. Esses comandos são procedimento proposto; não foram executados contra nós HAD nesta auditoria.

Aceitação no teste precisa incluir captura de UDP entre os nós e confirmação de tabela remota/decisão; `PEER PING` não basta. Para provar influência numérica, formar histórico local/remoto real suficiente para a correlação e executar STORE; uma só mensagem REPUTATION não prova combinação ativa. Testar reinício, backup/restore de peer.map, firewall permitindo apenas HAD e inexistência de tráfego público.

## Híbrido e dependência Matrix

Uma lista de peers pode conter HAD e públicos; não há condição no construtor que obrigue `.spfbl.net` (`Peer.java:144-152`, `:566-577`). Matrix é peer especial de bootstrap e compatibilidade legada (`:1074-1075`, `:1089`), não um diretório global de peers consultado pelo core. `Core.isMatrixDefence():1622-1629` distingue o hostname Matrix para funções próprias, sobretudo Abuse; não transforma um nó HAD em Matrix.

O híbrido original oferece combinação **no nó que recebe as fontes**. Para que node02/node03 também consumam contadores públicos, eles precisariam de suas próprias relações autorizadas com peers públicos; node01 não reexporta automaticamente o binomial público agregado. Uma ponte com separação por fonte não existe no código auditado. Uma central HAD única consultada por vários MTAs pode compartilhar a mesma decisão/reputação central sem exigir três cores P2P.

Matrix não é obrigatória para P2P lógico HAD, mas remover seed/configuração não elimina os outros serviços `*.spfbl.net` usados pelos clientes e pela classe Abuse. Consulte [SPFBL-EXTERNAL-SERVICES.md](SPFBL-EXTERNAL-SERVICES.md).

## Evidência obtida e validações pendentes

Buscas locais reproduzíveis:

```powershell
rg -n 'Peer\.load\(|loadCache\(|peerUDP\s*=' src
rg -n 'HELO|REPUTATION|BLOCK|Cipher|getSendAllSet|processBlock' src/net/spfbl/core/Peer.java src/net/spfbl/service/ServerP2P.java
rg -n 'addFQDN|isReservedIP|isReservedIPv4|isReservedIPv6' src/net/spfbl/data/FQDN.java src/net/spfbl/whois
rg -n 'matrix\.spfbl\.net|PEER' src run client
```

O fluxo e seus limites foram conferidos no texto fonte. Execução real de malha HAD, handshake HTTPS, comportamento P2PS em processo, autorização pública, latência/carga e envenenamento com decisão efetiva são **NÃO CONFIRMADOS** nesta etapa. Nenhum endpoint público foi consultado para completá-los.
