# Auditoria de segurança do SPFBL

Registro parcial do baseline original `7b0232e96f16faca151340b80c418838a800237f`. O scan Codex Security `f2207a83-1932-46eb-9a3a-8f2351b62cfd` foi cancelado em 2026-10-01; as evidências abaixo não formam uma auditoria completa. As reproduções usaram o core compilado das fontes originais e uma rede Docker `--internal`; não houve teste contra serviços SPFBL públicos ou alteração do cPanel de homologação. O projeto segue focado em preparar e desenvolver o anti-spam HAD baseado no core SPFBL, não em ampliar esta busca de falhas.

## Resumo executivo

| Severidade | Quantidade | Pontos comprovados nesta rodada |
|---|---:|---|
| Alta | 3 | Mutação ADMIN sem autenticação, reclamação de IP anônima que altera reputação e atualização de shell executada como root via TCP sem integridade. |
| Média | 5 | Bloqueio do dispatcher ADMIN por leitura lenta, SSRF cego a loopback/redirecionamento, senha aceita em HTTP sob configuração sem TLS, overflow P2P que gera status GREEN e limite de memória SpamD contornável. |

Separadamente, o listener SMTP experimental tem uma saturação reproduzida com oito clientes lentos, mas **não inicia no build padrão**, pois `Core.TESTING=false`. Esse resultado não entra na contagem dos oito achados; corrigir antes de habilitar/reintroduzir esse listener.

As severidades são condicionais ao alcance do serviço e às pré-condições descritas em cada achado. A lista não representa aprovação do produto: SMTP/MIME além do caso de conexão lenta, feedback/tickets, CSRF, configuração real do proxy HTTPS, P2P real e outros fluxos ainda requerem fechamento.

## Método e limites

O alvo estático é o commit original acima; a revisão cobriu o código distribuído, scripts de cliente/instalação e configuração. Os ensaios foram restritos a containers de laboratório e rede Docker interna ou `--network none`, usando fixtures locais, sem acessar peers públicos, usuários reais ou conteúdos de e-mail. Para habilitar o listener experimental do SMTP em laboratório, uma cópia local da classe `Core` teve somente a constante de modo de teste ligada; a implementação `ServerSMTP` permaneceu idêntica à do baseline. Nenhuma alteração foi feita no core do repositório.

O cPanel `grupoguedes.hadcloud.srv.br` foi inspecionado somente em leitura em 2026-10-01 22:46 UTC: cPanel `11.138.0.11`, Exim `4.100.1`, Imunify Email `2.3.0-1`, Rspamd ativo e `ie-dec-node` em `auto-restart`; filtragem de entrada e quarentena Imunify estavam ativas. Os arquivos ACL customizados observados estavam vazios. Esse inventário não valida integração HAD nem permite concluir comportamento após rebuild/rollback; esses ensaios não foram feitos no servidor. Ver [cpanel-baseline.json](evidence/cpanel-baseline.json).

## Achados reproduzidos no build padrão ou em fluxos habilitáveis por configuração

### ADMIN: comandos de alteração sem autenticação — CWE-306

**Alta, condicionada ao acesso TCP à porta ADMIN.** `AdministrationTCP` aceita uma conexão, lê o comando e chama o dispatcher com o resultado de `Client.get(ipAddress)`, inclusive quando não existe cadastro. O comando `CLIENT ADD` chega a `Client.create` sem uma verificação de identidade/permissão administrativa ([AdministrationTCP.java:125](../src/net/spfbl/core/AdministrationTCP.java#L125), [AdministrationTCP.java:2857](../src/net/spfbl/core/AdministrationTCP.java#L2857)). Um cliente de outro container, sem cadastro e com IP não loopback, adicionou, confirmou e removeu um cliente no sandbox. A porta vinculada a interfaces de rede exige filtro de firewall externo; isso reduz exposição, mas não substitui autenticação.

### ADMIN: cliente lento bloqueia o dispatcher — CWE-400

**Média, condicionada ao acesso TCP à porta ADMIN.** O mesmo loop sequencial executa `readLine()` sem timeout por socket. Manter uma conexão aberta sem terminar a linha impediu `VERSION` em uma segunda conexão; ao fechar a primeira, `VERSION` voltou a responder. O ensaio bloqueou o dispatcher ADMIN, não o listener SPFBL nem o processamento SMTP. Vetor e transcrição constam em `artifacts/02_discovery/admin-audit-results.json` do scan `f2207a83-1932-46eb-9a3a-8f2351b62cfd`.

### SpamD: tamanho declarado não limita o corpo lido — CWE-400

**Média, condicionada ao alcance TCP da porta SPFBL.** O handler verifica se o `Content-length` declarado excede `ServerSMTP.SIZE` (16 MiB), mas acumula o corpo em `ByteArrayOutputStream` até EOF sem comparar os bytes lidos com o valor declarado nem impor um teto adicional ([ServerSPFBL.java:609](../src/net/spfbl/service/ServerSPFBL.java#L609), [ServerSPFBL.java:629](../src/net/spfbl/service/ServerSPFBL.java#L629), [ServerSPFBL.java:634](../src/net/spfbl/service/ServerSPFBL.java#L634)). Uma origem sem autenticação pode declarar um corpo pequeno e manter o socket enviando dados; a memória cresce com o conteúdo recebido. O handler possui limite de conexões, mas não um limite de bytes efetivamente armazenados.

**Prova local:** no listener SPFBL padrão, em rede Docker interna, o harness anunciou `Content-length: 1`, enviou 16.777.217 bytes e recebeu `SPAMD/1.0 67 EX_NOUSER`, em vez da rejeição de mensagem grande `EX_NOPERM`. O caminho de leitura até EOF é confirmado no código. O teste não pressionou o heap até OOM e não mediu impacto em outros serviços; portanto, exaustão global de memória é o impacto possível, não um resultado observado. Evidência: [spamd-content-length.json](evidence/spamd-content-length.json) e [harness](../packaging/audit/SpamdFramingAudit.py).

### Consulta SPFBL permite reclamar de qualquer IP sem autenticação — CWE-862

**Alta, condicionada ao alcance TCP da porta SPFBL (padrão 9877).** O handler deriva `client` do IP de origem, mas não encerra a conexão quando não há cadastro; comandos comuns seguem para `SPF.processSPF` com `client=null` ([ServerSPFBL.java:426](../src/net/spfbl/service/ServerSPFBL.java#L426), [ServerSPFBL.java:1600](../src/net/spfbl/service/ServerSPFBL.java#L1600)). A ramificação `ABUSE <IP>` chama `SPF.addComplainSafe` sem ticket, credencial ou prova da mensagem, em seguida tenta banir pelo cliente nulo e marca sinais harmful ([SPF.java:4937](../src/net/spfbl/spf/SPF.java#L4937), [SPF.java:4977](../src/net/spfbl/spf/SPF.java#L4977)). `addComplain` aceita o IP se não estiver em `Ignore`, adiciona evento SPAM e tenta distribuir a reputação ([SPF.java:2137](../src/net/spfbl/spf/SPF.java#L2137)).

**Prova local:** uma conexão TCP da rede Docker interna, sem cliente cadastrado, enviou `ABUSE 8.8.4.4` e recebeu `COMPLAINED 8.8.4.4`. Em harness isolado, a chamada com `client=null` aumentou a amostra local do mesmo IP de 0 para 1 SPAM. A variante `ABUSE In-Reply-To:<id> From:<email>` também aceitou `client=null`, confiou no `From` declarado e alterou uma consulta sintética pertencente ao usuário indicado; a resposta foi `BLOCKED` e o evento passou a constar como SPAM ([SPF.java:4937](../src/net/spfbl/spf/SPF.java#L4937), [SPF.java:4969](../src/net/spfbl/spf/SPF.java#L4969), [User.java:2597](../src/net/spfbl/core/User.java#L2597)). Não havia peer na fixture, logo propagação P2P não foi testada. Evidências: [unauth-abuse-ip.json](evidence/unauth-abuse-ip.json) e [unauth-abuse-message.json](evidence/unauth-abuse-message.json).

### Risco de ativação: oito conexões lentas esgotam o listener SMTP experimental — CWE-400

**Reproduzido, mas não aplicável ao build padrão atual.** `ServerSMTP` usa oito workers por padrão (`CONNECTION_LIMIT`) e chama `BufferedReader.readLine()` para aguardar comandos sem aplicar timeout de leitura ao socket ([ServerSMTP.java:5388](../src/net/spfbl/service/ServerSMTP.java#L5388), [ServerSMTP.java:7012](../src/net/spfbl/service/ServerSMTP.java#L7012)). Ao esgotar o pool, novas conexões recebem `421 Too many concurrent SMTP connections` ([ServerSMTP.java:275](../src/net/spfbl/service/ServerSMTP.java#L275)). Contudo, `Core.TESTING=false` no baseline impede iniciar esse listener experimental; a prova ativou essa guarda somente numa cópia local de `Core`, mantendo `ServerSMTP` original.

**Prova local:** oito clientes na rede Docker interna receberam banner `220` e ficaram conectados sem enviar comandos; a nona recebeu `421`. Depois de fechar as oito, uma nova conexão recebeu `220`. Não houve autenticação, submissão ou mensagem de teste. Evidência: [smtp-slow-client.json](evidence/smtp-slow-client.json) e [harness](../packaging/audit/smtp-slow-client-audit.py).

### Consulta manual de URL: SSRF cego, incluindo redirecionamento a loopback — CWE-918

**Média, condicionada à publicação da interface HTTP.** O POST `/` aceita URL válida de um visitante sem sessão e cria uma rota `.url` ([ServerHTTP.java:1050](../src/net/spfbl/service/ServerHTTP.java#L1050)). O GET da rota chama `getDNSBLHTML`; o processamento em background abre `HttpURLConnection` para a URL fornecida, sem negar endereços privados/locais ([ServerHTTP.java:3664](../src/net/spfbl/service/ServerHTTP.java#L3664), [ServerHTTP.java:6627](../src/net/spfbl/service/ServerHTTP.java#L6627)). O código segue respostas 301/302/303, aceita uma nova URL absoluta e repete a checagem sem validar a rede de destino ([ServerHTTP.java:6612](../src/net/spfbl/service/ServerHTTP.java#L6612), [ServerHTTP.java:6741](../src/net/spfbl/service/ServerHTTP.java#L6741)).

**Prova local:** sem cookie ou credencial, o POST retornou HTTP 200 e uma rota `.url`; o GET dessa rota fez o processo SPFBL acessar `127.0.0.1:18081/redirect-run2` e seguir `Location` até `127.0.0.1:18081/final`. O fixture recebeu as duas requisições pelo loopback dentro do namespace de rede do container SPFBL. A rede era interna, sem rota de saída pública, e não continha serviço ou dado real. Evidência: [http-ssrf.json](evidence/http-ssrf.json) e [http-ssrf-lab.md](evidence/http-ssrf-lab.md).

O achado é classificado como cego: a resposta HTML indica resultado da checagem, mas o corpo textual do fixture não foi devolvido ao cliente. Portanto a prova sustenta requisição e exploração de redirecionamento a um destino local, não exfiltração de conteúdo, execução de código ou impacto em endpoint específico.

### Atualizador de firewall: resposta TCP sem integridade executada como root — CWE-494

**Alta, condicionada à função de firewall estar habilitada e a um atacante conseguir interferir no caminho ou controlar o servidor da resposta.** O instalador busca `firewall.cpanel.sh` por HTTPS e executa esse atualizador ([spamfox.cpanel.sh:301](../client/spamfox.cpanel.sh#L301)). O script abre uma conexão TCP sem TLS para `54.233.253.229:9877`, salva a resposta como `/usr/local/bin/spfbl-firewall`, marca executável e a executa; o atualizador também fica ligado ao cron horário ([firewall.cpanel.sh:8](../client/firewall.cpanel.sh#L8), [firewall.cpanel.sh:47](../client/firewall.cpanel.sh#L47)). Assim, uma resposta adulterada pode se tornar código shell com privilégios root no host.

**Prova do sink:** em um container Debian efêmero com `--network none`, um stub local substituiu `nc` e devolveu apenas um script inofensivo que gravou `id -u`; a rotina executou o payload como UID `0`. Isso comprova escrita/chmod/execução como root, mas não a capacidade de um agente externo interceptar a rota ou o controle atual do destino fixo. A opção precisa estar ativada; não foi executada no cPanel HAD. Evidência: [firewall-cleartext-execution.json](evidence/firewall-cleartext-execution.json) e [harness](../packaging/audit/firewall-cleartext-harness.sh).

### Login web aceita senha por HTTP sem TLS — CWE-319

**Média, quando o listener HTTP está publicado sem redirect TLS externo.** A configuração distribuída habilita `http_port=80` e deixa `https_port=443` comentado ([spfbl.conf:55](../run/spfbl.conf#L55)). O handler só redireciona HTTP quando o servidor HTTPS está iniciado, o hostname não é `localhost` e o certificado não está expirando ([ServerHTTP.java:3034](../src/net/spfbl/service/ServerHTTP.java#L3034)). Sem essas condições, o login processa `password` normalmente mesmo no handler não seguro ([ServerHTTP.java:1108](../src/net/spfbl/service/ServerHTTP.java#L1108)); o formulário usa POST na própria origem sem destino HTTPS ([ServerHTTP.java:6115](../src/net/spfbl/service/ServerHTTP.java#L6115)). Um visitante que acesse essa configuração diretamente pode enviar senha e receber cookie pela rede sem TLS. O cookie também não define `Secure`, `HttpOnly` ou `SameSite` ([ServerHTTP.java:544](../src/net/spfbl/service/ServerHTTP.java#L544)).

O impacto prático depende de HTTPS do core ou redirect do proxy frontal. Não transmiti credenciais de teste em claro; a evidência é a configuração e o trace do handler/form. Ver [http-login-transport.json](evidence/http-login-transport.json).

### Overflow de contadores P2P contorna o cap e marca reputação como GREEN — CWE-190

**Média, condicionada a um peer já autorizado para receber reputação e com `reputationMax > 0`.** O parser P2P passa os inteiros recebidos para `Peer.setReputation` ([ServerP2P.java:395](../src/net/spfbl/service/ServerP2P.java#L395), [Peer.java:1214](../src/net/spfbl/core/Peer.java#L1214)). O setter rejeita valores negativos, mas aceita `Integer.MAX_VALUE`; `Binomial.getTotalSize()` soma HAM e SPAM em `int`, podendo retornar `-2` ([Peer.java:1431](../src/net/spfbl/core/Peer.java#L1431)). A agregação compara essa soma ao cap e, devido ao overflow, não limita os contadores; depois também soma em `int`, calcula probabilidade negativa e atualiza o status para `GREEN` ([SPF.java:7625](../src/net/spfbl/spf/SPF.java#L7625), [SPF.java:7642](../src/net/spfbl/spf/SPF.java#L7642), [SPF.java:7672](../src/net/spfbl/spf/SPF.java#L7672)).

**Prova local:** as classes originais calcularam correlação `1,00000008` com 40 tokens sintéticos, concederam cap `256`, aceitaram `2147483647` HAM e SPAM de um peer sintético `ACCEPT`, e observaram o total recebido `-2`. Para token com histórico local 12/12, a probabilidade passou de `0,25` para `-97612896`, e o status resultou em `GREEN`. O processo rodou em Docker com `--network none`; nenhum peer real foi contatado. A prova demonstra a falha aritmética e o estado interno, não uma decisão SMTP nem o efeito em uma instalação cPanel. Evidência: [reputation-overflow.json](evidence/reputation-overflow.json) e [harness](../packaging/audit/ReputationOverflowAudit.java).

## Correção recomendada

- Restringir o fetch a HTTP/HTTPS e rejeitar loopback, RFC1918, link-local, multicast, endereços não especificados e equivalentes IPv6 após resolução DNS.
- Repetir validação de endereço para cada redirecionamento e impedir mudança de esquema; limitar saltos, respostas e duração total.
- Adicionar limites de concorrência e taxa para a consulta assíncrona; preferir egress controlado em rede como defesa adicional.
- Remover o canal TCP de atualização executável; distribuir pacote assinado com verificação criptográfica independente e instalar dados declarativos com validação estrita.
- Proteger o ADMIN com autenticação/autorização antes do dispatcher e prazo/limite de linha por conexão.
- No protocolo SpamD, rejeitar `Content-length` inválido ou acima do teto, ler exatamente esse número de bytes com limite rígido, rejeitar corpo truncado e impor timeout de leitura; nunca acumular dados até EOF sem quota.
- Exigir autenticação/ticket verificável e limitação por origem para reclamações; não aceitar `ABUSE <IP>` sem comprovação vinculada à mensagem e ao destinatário.
- Validar limites superiores e somar contadores em tipo mais largo com checagem; rejeitar snapshots impossíveis antes de persistir e antes de calcular correlação, cap ou status.
- Desabilitar o listener HTTP para login ou redirecionar antes do handler; exigir HTTPS na aplicação e emitir cookies `Secure`, `HttpOnly` e `SameSite` explícitos.

## Superfícies ainda abertas

O scan global continua parcial. CSRF e path traversal foram triados no código, mas não passaram por browser PoC/ensaio de bypass: a alteração de política fica no ramo POST, e `getWebFile` rejeita `../` após decodificação da rota; não há achado confirmado nessas duas hipóteses. Permanecem pendentes parsing SMTP/MIME e limites, outros fluxos de feedback/tickets, validação dinâmica de sessão, regras e confiança P2P, persistência de reputação e canais de atualização. Os achados acima não aprovam enforcement em produção.
