# Auditoria de reputação, tickets e aprendizado SPFBL

Auditoria estática offline em 2026-10-01. Referência: commit `7b0232e96f16faca151340b80c418838a800237f` do checkout atual. As referências `arquivo:linha` apontam para esse código, não para documentação externa ou para um serviço em produção. O core original não foi alterado nesta auditoria.

**Conclusão:** existem dois modelos de reputação coexistentes. `net.spfbl.spf.SPF.Distribution` mantém eventos HAM/SPAM e agrega contadores recebidos de peers. `net.spfbl.data.Reputation` mantém somas suavizadas e flags hierárquicas locais. Tratar ambos como um único score ou presumir que todas as flags locais são replicadas pelo P2P produziria uma descrição incorreta do baseline.

Este documento comprova fluxos de código. Execução em produção, entrega real, qualidade estatística, eficácia antiabuso, participação na rede pública e restauração integral permanecem **NÃO CONFIRMADOS**. Os resultados dos testes offline, quando executados pelo fluxo da auditoria, são registrados em `docs/TEST-RESULTS.md`; os casos adicionais abaixo são propostas de validação e não resultados presumidos.

## 1. Inventário dos modelos e separação de origem

| Camada | Classe, campo e leitura | Persistência | O que significa |
|---|---|---|---|
| Binomial local | `spf.SPF.Distribution.hamSet/spamSet`, `getSpamProbability()`; `src/net/spfbl/spf/SPF.java:7367`, `:7376`, `:7597` | `SPF.CacheDistribution`, `./data/reputation.txt`; `SPF.java:2646`, `:2698`, `:2824` | Eventos observados por este servidor, identificados por timestamp; HAM/SPAM não são os valores das flags modernas. |
| Binomial de um peer | `core.Peer.reputationMap2`, `Peer.Binomial.ham/spam`, `setReputation()`, `getReputation()`; `src/net/spfbl/core/Peer.java:95`, `:1214`, `:1371`, `:1391` | `./data/peer.map`, `Peer.store/load`; `Peer.java:1002`, `:1022` | Cópia por peer, com última atualização própria; recebimento não insere esses eventos no `hamSet/spamSet` local. |
| Agregação local + peers | `Distribution.getSpamProbability(token, limit)` e `getBinomial(token)`; `SPF.java:7617`, `:7755` | Resultado calculado em leitura; `status`/`good` são campos locais da distribuição | Não há um campo separado chamado `global reputation`; o resultado usa o histórico local e peers habilitados por `reputationMax`. |
| Flags locais hierárquicas | `data.Reputation.xiSum/xi2Sum/last/flag/minimum/maximum`; `src/net/spfbl/data/Reputation.java:39` | Arquivos de cada entidade, listados na seção 8 | Classificação `HARMFUL` a `BENEFICIAL`, com suavização por evento e herança de hierarquia. |
| Listagem DNSBL externa | `Block.DNSBL.get(client, ip)` → `Reverse.getListedIP`; `src/net/spfbl/data/Block.java:739`, `:780` | Configuração de listas em Block; não há importação de contadores HAM/SPAM nesse método | Sinal externo identificado como `DNSBL=servidor;resposta`, ou prefixado por cliente. |

Os nomes futuros `HAD_LOCAL`, `SPFBL_P2P` e `EXTERNAL_DNSBL` do escopo não existem como contrato unificado neste baseline. Há dados suficientes para distinguir algumas origens, mas o resultado SMTP não fornece automaticamente uma explicação completa das contribuições. `Filterable.getListedDNSBL()` consulta `Block.findDNSBL` (`src/net/spfbl/core/Filterable.java:1327`); o detalhe dos endpoints externos está em `SPFBL-EXTERNAL-SERVICES.md`.

## 2. HAM/SPAM binomial: fórmula, limiares, tempo e peers

### 2.1 Contagem local

`Distribution.getSpamProbability()` calcula exatamente:

```text
H = hamSet.size()
S = spamSet.size()
P_local = 0, quando H + S = 0
P_local = S / (H + S), nos demais casos
```

Evidência: `src/net/spfbl/spf/SPF.java:7597`, classe `SPF.Distribution`, método `getSpamProbability()`.

`addSpam(time)` remove o timestamp de HAM e o insere em SPAM; `addHam(time)` faz o inverso (`SPF.java:7728`, `:7740`). `TreeSet` elimina repetição do mesmo timestamp. Uma reclamação repetida não multiplica o evento nessa distribuição. `removeSpam(time)` adiciona HAM e remove SPAM, e retorna `true` mesmo se a remoção não mudou o set (`SPF.java:7712`). Isso exige cuidado: uma resposta `OK` de remoção não comprova alteração efetiva nem a flag moderna correspondente.

`SPF.addQueryHam()` insere observação inicial e produz ticket (`SPF.java:7038`, `:7074`); `SPF.addQuerySpam()` registra SPAM e chama `Peer.sendToAll` quando o token não é ignorado (`SPF.java:7112`, `:7153`). `SPF.setHam/setSpam()` ajustam os sets e o status, mas **não chamam `Peer.sendToAll` diretamente** (`SPF.java:7087`, `:7099`). Os fluxos de reclamação têm envio explícito próprio.

### 2.2 Janela e corte

- `dropExpiredQuery()` remove timestamps anteriores a `agora - 604800000 ms` (7 dias), e depois executa `hairCut()` (`SPF.java:7470`).
- `hairCut()` remove o mais antigo entre HAM/SPAM até respeitar `Core.getReputationLimit()` (`SPF.java:7718`). Esse limite é constante `256`, não uma propriedade configurável identificada (`src/net/spfbl/core/Core.java:2325`). Portanto 7 dias não significa retenção de todos os eventos dos últimos 7 dias: fontes de alto volume retêm no máximo 256 eventos.
- `CacheDistribution.get()` reseta distribuição cuja última consulta ficou sem atividade por mais de 7 dias (`SPF.java:2926`). `CacheDistribution.store()` descarta distribuições sem consulta há mais de 14 dias e limpa eventos antigos (`SPF.java:2824`). O descarte não ocorre a cada leitura de `getSpamProbability()`.
- `frequency` usa `NormalDistribution` para intervalos entre consultas, separadamente da fração SPAM. `addQueryHam/Spam` atualizam a frequência; `addHam/Spam` de feedback não atualizam `lastQuery` nem a frequência (`SPF.java:7569`, `:7583`, `:7728`; `src/net/spfbl/core/NormalDistribution.java:33`, `:91`).

### 2.3 Agregação P2P e confiança

`getSpamProbability(token, limit)` começa com os contadores locais, percorre `Peer.getPeerList()` e só usa peers com `reputationMax > 0`. Para cada peer, se `H_peer + S_peer > reputationMax`, reduz proporcionalmente os dois contadores e faz conversão para inteiros. Então soma às observações locais (`SPF.java:7617`). Não há um peso universal igual para todos os peers.

**Achado reproduzido no baseline:** `Peer.Binomial` aceita cada contador até `Integer.MAX_VALUE`; somar HAM+SPAM em `int` pode produzir total negativo. Nesse caso a condição de escala pelo cap não é acionada, e a soma aos contadores locais também pode exceder o intervalo de `int`, produzindo probabilidade negativa e `GREEN`. O teste isolado com peer sintético e cap calculado está em `docs/evidence/reputation-overflow.json`; não foi testado impacto SMTP ou em serviço de produção. Ver [laudo de segurança](SPFBL-SECURITY-AUDIT.md#overflow-de-contadores-p2p-contorna-o-cap-e-marca-reputação-como-green).

`Peer.refreshReputationMax()` define `max((int)(256 * correlação), 0)` (`Peer.java:1287`). `Peer.getCorrelacao()` compara probabilidades **locais** e daquele peer, requer mais de 32 tokens em comum e mais de 7 eventos em cada lado por token; abaixo disso retorna zero (`Peer.java:230`). A fórmula é correlação de Pearson; correlação nula/negativa elimina a contribuição. Isso é um limite por peer, não autenticação, prova de honestidade ou orçamento global contra múltiplos peers. Ver análise completa em `SPFBL-P2P-AUDIT.md`.

Depois da soma:

1. Se o total é menor que `limit`, retorna `null`; o overload habitual usa `limit = 8`, convertendo `null` em `0.0` (`SPF.java:7608`, `:7617`). Ausência de amostra pode aparecer como probabilidade zero nesse overload.
2. Calcula `S_total / (H_total + S_total)`.
3. Aplica, nesta ordem: se `P > 0.25` e `S < 32`, devolve `0.25`; se `P > 0.50` e `S < 64`, devolve `0.50`; se `P > 0.75` e `S < 128`, devolve `0.75`; caso contrário devolve a fração (`SPF.java:7648`). Portanto o resultado agregado nem sempre é a fração bruta.
4. Após uma semana desde a criação, atualiza `good = H_total > 512 && S_total < 32` (`SPF.java:7639`). Com limite local 256, `good` depende de contribuições adicionais para ultrapassar 512.

`getStatus(token)` usa histerese: `P < .25` → GREEN, `P > .50` → RED; no intervalo mantém RED anterior, caso contrário YELLOW (`SPF.java:7674`). Os operadores são estritos; .25 e .50 não equivalem aos lados abaixo/acima. O `status` é atualizado pelas leituras que chamam essa máquina de estados.

## 3. Modelo moderno: valores, fórmula e decay

`Reputation.Flag` codifica `HARMFUL=-4`, `UNDESIRABLE=-2`, `UNACCEPTABLE=-1`, `ACCEPTABLE=1`, `DESIRABLE=2`, `BENEFICIAL=4` (`src/net/spfbl/data/Reputation.java:46`, `:115`). Maior magnitude negativa significa evidência pior; HAM empurra a média para valores positivos. Não se deve denominar `-4` como quatro SPAMs.

Para valor `v` e população `N`, `Reputation.add(v,N)` faz (`Reputation.java:245`):

```text
xiSum'  = xiSum  * (1 - 1/N) + v
xi2Sum' = xi2Sum * (1 - 1/N) + v*v
last'   = TIME
media   = xiSum / N
```

Assim há perda de influência **por novo evento**. Após `k` novos eventos, a contribuição antiga é multiplicada por `(1-1/N)^k`; não há redução contínua das somas simplesmente porque o relógio avançou no método `add`. A população altera a memória efetiva, não a janela de sete dias do modelo binomial.

`getAvgStd()` calcula `(xi2Sum - 2*media*xiSum + N*media²)/(N-1)` e chama a variável resultante `std`; `refreshFlag()` usa `media ± 2*std` (`Reputation.java:260`, `:372`). **O código não aplica raiz quadrada nessa variável**. Este documento preserva a fórmula implementada; não a interpreta como desvio-padrão convencional nem altera o core.

Antes de existir flag, `flag` é um contador `Integer`; a primeira classificação exige `count >= N`. A média arredondada determina o nível inicial. Depois há uma máquina de estados com diferentes limiares de entrada/saída e restrição `reserved`, em vez de recalcular apenas `Flag.getFlag(media)` (`Reputation.java:378`, `:482`). Os valores de `minimum/maximum` são limites derivados arredondados, não os menores/maiores eventos brutos observados.

`TIME = (int)(System.currentTimeMillis() >>> 32)` (`Reputation.java:227`). Um tick é `2^32 ms`, aproximadamente 49,71 dias; não é epoch em segundos. `isExpired()` compara diferença de ticks `>1`; o overload usa `>expiration` (`Reputation.java:237`). `getFlag()` atualiza `last = TIME` inclusive em leitura (`Reputation.java:297`, `:306`). O descarte de nós representa inatividade de atualização **ou consulta** em ticks grosseiros; não deve ser confundido com decay exponencial de calendário. `Server.storeAll()` chama `Reputation.refreshTime()` (`src/net/spfbl/core/Server.java:266`).

## 4. Entidades e hierarquias modernas

| Entidade | Classe e fluxo confirmado | População/particularidades | Arquivo |
|---|---|---|---|
| IP/rede IPv4 | `data.CIDR.add*` → `ProcessThread` → árvore `ROOTREP4`, do /0 ao /32; `CIDR.java:55`, `:193`, `:347` | `POPULATION4`: 32768 no /0 até 756 no /32; ±4 reduzidos a ±2 até /24 e a ±1 até /16; `CIDR.java:1546`, `:1634` | `./data/cidr.txt`; `CIDR.java:372` |
| IP/rede IPv6 | `ROOTREP6`, usa `SubnetIPv6.getAddressLong` e percorre somente até /64; `CIDR.java:170`, `:322` | `POPULATION6`: 65536 no /0 até 1353 no /64; ±4 reduzidos a ±2 até /48 e a ±1 até /32; `CIDR.java:1553`, `:1646` | O mesmo arquivo, registros `REP6`; `CIDR.java:483`, `:1619` |
| FQDN validado | `data.FQDN`, domínio em árvore reversa até nível 7; `FQDN.java:577`, `:715` | Populações 16384,8192,4096,2048,1024,512,256,128; ignora FQDN genérico nesse aprendizado, ajusta Ignore/Provider/TLD/reservados; `FQDN.java:718`, `:1180` | `./data/fqdn.txt`; `FQDN.java:432` |
| HELO | `data.Generic.add*` → máscara `convertHostToMask` → árvore; leitura `Generic.getFlag(helo)`; `Generic.java:1008`, `:1228` | Populações 16384 até 128; HELO não hostname retorna UNACCEPTABLE. A chave pode ser máscara, não HELO literal; `Generic.java:1231`, `:1266` | `./data/generic.txt`; `Generic.java:844` |
| Domínio/envelope sender | `data.SPF.add*` somente se SPF PASS; árvore reversa de domínio e local-part para freemail; `data/SPF.java:201`, `:397`, `:434`, `:451` | Domínio: 16384 até 128; local-part freemail: 64. A variável `recipient` nesta classe é local-part do **remetente**, não RCPT TO; `data/SPF.java:393`, `:619` | `./data/spf.txt`; `data/SPF.java:56` |
| Domínio DKIM | `data.DKIM`, assinantes e From; `DKIM.java:914`, `:1120` | Populações 16384 até 128; sem assinatura válida o resultado tende UNACCEPTABLE e conserva flags negativas; `DKIM.java:1124`, `:1153` | `./data/dkim.txt`; `DKIM.java:371` |
| Contato abuse | `data.Abuse`, endereço responsável por IP/FQDN; `Abuse.java:1431`, `:1598` | População 2048; `Abuse.java:1530` | `./data/abuse.txt`; `Abuse.java:1198` |
| Destinatário/usuário | `data.Recipient`, chave do usuário e `userEmail:recipientEmail`; `Recipient.java:235`, `:309`, `:948` | População 1024; reputação geral do usuário precede a individual; root reduz ±4 para ±2; `Recipient.java:976` | `./data/recipient.txt`; `Recipient.java:521` |
| Assunto e links | `Dictionary.add*` e `URI.add*` chamados por `User.Query.add*`; `core/User.java:4366`, `:4368`, `:4494` | Também são aprendizado local; não são campos do pacote P2P REPUTATION | `./data/dictionary.txt`, `./data/uri.txt`; `Dictionary.java:903`, `URI.java:609` |

IPv6 não tem reputação moderna distinta por /128: endereços no mesmo /64 compartilham o nó final. Isso não impede outros mecanismos de lista/CIDR ou tokens binomiais de representarem IPv6; `spf.SPF.isValidReputation` aceita IP público (`SPF.java:4845`). Não se deve inferir uma granularidade única para todas as estruturas.

**ASN:** há `whois.AutonomousSystem` e cache WHOIS (`src/net/spfbl/whois/AutonomousSystem.java:38`, `:376`, `:411`; `core/Server.java:135`), mas não foi identificado campo reputacional HAM/SPAM/Flag por ASN no fluxo auditado. `isValidReputation` aceita IP, `.hostname` e remetentes/domínios; não aceita um token ASN dedicado (`SPF.java:4845`). Reputação por ASN é **NÃO CONFIRMADA**; metadata WHOIS e reputação CIDR não provam esse requisito.

As raízes de CIDR/FQDN/Generic/SPF/DKIM são estáticas globais ao processo. Somente o modelo Recipient aqui demonstrado inclui usuário/cliente na chave. Isso permite que observações de um cliente afetem fontes usadas por outros clientes, comportamento compatível com aprendizado compartilhado, mas diferente de uma política de isolamento completo de reputação por tenant.

## 5. Decisão composta e pesos

`Reputation.getEnvelopeFlag()` obtém flags de CIDR, HELO, FQDN, abuse, sender e recipient e as entrega à `NeuralNetwork.getFlagEnvelope` (`Reputation.java:858`). Há um perceptron local com parâmetros constantes (`src/net/spfbl/data/NeuralNetwork.java:306`): bias `1.3097928`; pesos, na ordem acima, `0.19011468`, `0.29100075`, `0.120521516`, `0.573576`, `0.10465571`, `0.38046435`. O cálculo faz soma ponderada, arredonda para byte e mapeia a Flag (`NeuralNetwork.java:48`, `:320`). É uma combinação local de flags; não é a fórmula binomial nem uma consulta remota ao serviço score.

Outros métodos têm prioridade explícita diferente. Por exemplo, `Reputation.isUndesirable(ip,fqdn,helo,sender,qualifier,from,signerSet)` verifica DKIM negativo, depois sender positivo/negativo, depois FQDN ou HELO, finalmente CIDR (`Reputation.java:810`). Não existe uma ordem única comprovada para todos os protocolos/estágios. Os futuros níveis HAD local → P2P → externo precisam preservar ou redefinir conscientemente esses contratos.

## 6. Tickets e feedback: dois caminhos de aprendizado

### 6.1 Formato e chave

`SPF.createTicket(time, tokenSet)` monta `spam token...` e chama `Core.encryptURL` (`spf/SPF.java:6891`). `Core.encryptURL` comprime com Huffman, reserva os primeiros 8 bytes para timestamp little-endian e chama `Server.encryptURLSafe` (`core/Core.java:286`). `Server.getPrivateKey()` lê ou cria uma chave AES em `./data/server.key` (`core/Server.java:280`); os métodos AES/Base64 URL-safe estão em `Server.java:384`, `:442`. O ticket não é apenas um identificador aleatório persistido numa tabela. Manter a chave é necessário para decodificar os tickets antigos após restore/migração.

Além dos tokens reputacionais, os fluxos de consulta podem incluir `userEmail:` e `>recipient` para identificar usuário e destinatário (`spf/SPF.java:5694`; parsers em `SPF.java:2393`). `User.getQueryEntry(ticket)` extrai timestamp/usuário do ticket e busca a Query no usuário correspondente (`core/User.java:1971`). O destinatário não integra a contagem P2P enviada por `sendToAll`.

### 6.2 Reclamação binomial

```text
SPAM <ticket>
  → SPF.addComplainURLSafe(origin, ticket, result)
  → decodifica timestamp/tokens; exige comando "spam"
  → rejeita idade maior que 432000000 ms (5 dias)
  → expandTokenSet: token original + domínio responsável quando aplicável
  → Ignore? addHam : addSpam no timestamp original
  → recalcula status
  → Peer.sendToAll(token, distribuição) quando addSpam mudou o evento
```

Evidências: parser TCP em `spf/SPF.java:4890`; URL-safe em `SPF.java:2356`; fallback legado em `SPF.java:2161`; expansão em `SPF.java:6907`. O parâmetro `origin` serve para log nesse método, não seleciona um namespace separado para a reputação.

`HAM <ticket>` chama `deleteComplainURLSafe` → `removeSpam` → status → `Peer.sendToAll` (`SPF.java:5480`, `:2526`). O decoder URL-safe verifica 5 dias, porém o fallback legado `deleteComplain()` não faz a mesma verificação de idade (`SPF.java:2495`). Por isso não é correto afirmar que todo caminho HAM rejeita tickets antigos. Tickets inválidos e a cadeia de fallback precisam ser exercitados antes de expor novos endpoints HAD.

`addComplainURLSafe` e `deleteComplainURLSafe` alteram diretamente o modelo binomial. Não há chamadas diretas para `CIDR.add*`, `Generic.add*`, `FQDN.add*`, `data.SPF.add*` ou `DKIM.add*` nesses métodos. `User.Query.setSpam/setHam` também delegam apenas ao binomial (`core/User.java:5289`). Logo `Report Spam`/`Not Spam` não devem ser descritos como atualização imediata e idêntica de todas as flags modernas.

### 6.3 Classificação de mensagem e flags modernas

`User.Query.addHarmful(time)` ajusta `SPF.setSpam` e enfileira eventos negativos em abuse, CIDR, HELO, FQDN, sender SPF PASS, assinantes DKIM, assunto/links e Recipient. `addBeneficial(time)` faz o equivalente positivo e `SPF.setHam` (`core/User.java:4351`, `:4479`). Há exceções explícitas para mailer-daemon, bounce e feedback `ABUSE_SUBMISSION/USER_SPAM/USER_PHISHING` no aprendizado de Recipient.

O processamento de filtros chama esses métodos conforme a classificação; por exemplo, `CIDR_BENEFICIAL/FQDN_BENEFICIAL` levam a `addBeneficial`, e casos de spoofing ou malware levam a `addHarmful` (`core/User.java:7511`, `:7541`, `:7554`). `Reputation.add*` oferece um fluxo de envelope semelhante sem assunto/links/DKIM (`data/Reputation.java:968`, `:1104`). Os processadores são threads iniciadas por `Core`, de forma que enfileirar um evento não prova sua persistência imediata (`core/Core.java:2820`; `data/CIDR.java:79`, `:156`).

### 6.4 Compartilhamento realmente demonstrado

`Peer.sendToAll(token, Distribution)` envia `REPUTATION <token> <ham> <spam> [frequencyXi frequencyXi2]`, usando contagem **local**, não a agregação de outros peers (`core/Peer.java:791`, `:798`, `:810`). Só entra no bloco de envio quando `spam % 3 == 0` e há conexão/configuração P2P (`Peer.java:792`, `:807`). Não são enviados ticket, destinatário, Query, assunto, corpo, flags `xiSum/xi2Sum` modernas, nem definição do spamtrap por esse comando.

Flags negativas locais podem gerar entradas Block; por exemplo, `CIDR.ProcessThread` chama `Block.tryToDominoBlockIP` (`data/CIDR.java:213`), e FQDN pode bloquear e remover whitelist (`data/FQDN.java:752`). `Block` tem envio P2P próprio (`data/Block.java:511`, `:1040`), tratado na auditoria P2P. Esse caminho indireto não é replicação integral da árvore moderna. Replicação de todos os scores modernos entre servidores HAD é **NÃO CONFIRMADA**.

## 7. Spamtrap, inexistentes e listas

### 7.1 Criação e identificação

`Trap.MAP` é `HashMap<String,Long>`. Um registro com tempo anterior ao presente é trap; tempo futuro indica destinatário inexistente, e `Long.MAX_VALUE` indica inexistente permanente (`data/Trap.java:47`, `:208`, `:217`, `:226`). `addTrap` grava `0L`; `addInexistent` grava `agora + Core.getInexistentExpiresMillis()` (`Trap.java:249`, `:257`). Isso permite que um inexistente com prazo finito se torne trap depois do prazo; não é simplesmente uma lista de e-mails com booleano.

Há entradas globais `recipient`/`@domain` e entradas `clientEmail:recipient`/`userEmail:recipient`; `getTime` procura global e depois o escopo de usuário (`Trap.java:274`, `:302`, `:907`). `getTimeRecipient` combina resultado de Client/User pelo menor tempo (`Trap.java:891`). No TCP do cliente há `TRAP ADD`, `TRAP DROP`, `TRAP SHOW` (`service/ServerSPFBL.java:1248`, `:1274`, `:1300`); na administração há `TRAP` com `putTrap` e tempo opcional (`core/AdministrationTCP.java:2349`).

Também existe `Recipient.Type.TRAP`, com atualização automática de destinatário anteriormente inexistente mediante evento -4 e flag UNDESIRABLE/HARMFUL (`data/Recipient.java:959`). Não confundir esse tipo persistido em `recipient.txt` com registros de `Trap.MAP` em `trap.map`.

### 7.2 Penalização e distribuição

No fluxo de envelope, quando `recipientTrapTime != null`, primeiro chama `Reputation.addUnacceptable(...)` (-1). Se o tempo passou, gera ticket/result `TRAP`, e, com `Math.random() > 0.8`, chama `Block.addBlockKey`; retorna `SPAMTRAP` no SPFBL ou `DISCARD` no Postfix (`spf/SPF.java:6487`, `:6490`, `:6500`; `:4290`, `:4301`, `:4308`).

`SPF.getTicket()` nesse caminho cria/recupera Query e ticket, mas não insere diretamente HAM/SPAM (`SPF.java:6996`). Portanto a frase “cada hit de spamtrap vira imediatamente um SPAM compartilhado” é contrariada por esse caminho específico. Há penalização moderna -1 e bloqueio probabilístico; efeitos posteriores da Query dependem do processamento. O receptor recebe uma resposta de descarte, mas confirmação de descarte efetivo exige o MTA real.

`Trap` não chama `Peer.sendToAll/sendToOthers`: o cadastro/endereço da armadilha não aparece no pacote REPUTATION. Pode haver propagação indireta de Block ou de contadores quando outro fluxo os atualizar. Compartilhamento de eventos completos de spamtrap e cópia automática de `trap.map` entre peers são **NÃO CONFIRMADOS**.

### 7.3 Efeito de listas

Ignore pode substituir SPAM por HAM em reclamações binomiais (`spf/SPF.java:2196`, `:2412`), e limitar eventos negativos modernos a -1 em CIDR/FQDN/sender (`data/CIDR.java:167`, `data/FQDN.java:717`, `data/SPF.java:410`). Provider reduz severidade de domínio/FQDN em situações específicas (`data/FQDN.java:720`, `data/SPF.java:422`). Reputação pode adicionar/remover Block e White; são estruturas e decisões próprias, não apenas limiares de um número.

O baseline mantém entradas globais e escopadas em listas; um exemplo claro é DNSBL configurada globalmente e/ou por cliente (`data/Block.java:749`, `:765`). A autorização da interface administrativa é requisito distinto do namespace. Isolamento completo entre tenants e resistência a feedback fraudulento não estão provados apenas por essas chaves.

## 8. Persistência, backup e restore

`Server.loadCache()` carrega Clients, User, Peer, listas, Trap, ambos os SPFs e as entidades modernas (`core/Server.java:129`). `Server.storeAll()` salva essas estruturas sequencialmente (`Server.java:232`). Não há evidência de uma transação consistente única entre todos os arquivos.

| Dados | Artefato confirmado e ponto de carga/gravação |
|---|---|
| Eventos binomiais locais | `data/reputation.txt`: `ADDR`, `ADDH`, `ADDS`; `spf/SPF.java:2698`, `:7380`. Migra legado `data/distribution.map` se texto não existe (`SPF.java:2785`). |
| Peers, contadores recebidos, configuração/chaves de peers | `data/peer.map`, serialização Java; `core/Peer.java:1002`, `:1022`. |
| Chave dos tickets | `data/server.key`; `core/Server.java:280`. Preserve o arquivo mesmo se não houver tickets armazenados separadamente. |
| Clientes | `data/client.map`; `core/Client.java:1092`, `:1110`. |
| Usuários e Queries | `data/user.map`, arquivo temporário `.user.map`; `core/User.java:1282`, `:1290`, `:1324`. Histórico adicional `history/*.data` e `*.index`; `User.java:9651`. Há caminhos de banco em `User.storeDB/storeDB2` (`User.java:3286`, `:3297`). |
| Spamtrap | `data/trap.map`, serialização de mapa; `data/Trap.java:947`, `:964`. Também `data/recipient.txt` para tipos de destinatário. |
| Listas | `data/block.txt`, legados `block.set/block.map`; `data/Block.java:3662`, `:3684`. `data/white.set`, `data/ignore.set` e arquivos CIDR próprios; `data/White.java:1827`, `data/Ignore.java:403`, `:90`. |
| Flags modernas | `data/cidr.txt`, `fqdn.txt`, `generic.txt`, `spf.txt`, `dkim.txt`, `abuse.txt`, `recipient.txt`, `dictionary.txt`, `uri.txt`; ver tabela da seção 4. |

Os arquivos modernos têm append para registros e fila, mais compactação para arquivo temporário seguida de `Files.move(..., REPLACE_EXISTING)`. Exemplo: `data.SPF.load/store`, `SPF.java:108`, `:148`; CIDR `CIDR.java:424`, `:514`. A gravação de snapshot inclui somas, flags/contadores de aprendizagem, extremos, hierarquia e filas pendentes. As flags modernas não são recuperáveis apenas a partir de `peer.map` ou dos totais HAM/SPAM.

Não se pode prometer durabilidade evento a evento. `Distribution.addHam/addSpam` muda sets em memória, e a serialização dos eventos está em `Distribution.store` (`spf/SPF.java:7380`, `:7728`); o helper `CacheDistribution.append` existe, mas não foi encontrado um uso de gravação por esses métodos. No modelo moderno, `refreshFlag` faz append quando **a flag muda**, não a cada amostra, por exemplo `FQDN.java:1277` e `data/SPF.java:801`. Snapshot e encerramento correto precisam ser considerados no RPO.

O backup inicial deve guardar uma cópia consistente de **todo `data/`**, configuração/runtime compatíveis e `history/`; se a implantação usa banco, incluir esse banco. Na restauração, `server.key` precisa acompanhar os dados da instância emissora para conservar tickets antigos. Reaproveitar a mesma chave em novas instâncias muda o domínio de confiança dos tickets; não é uma solução automática de compartilhamento de reputação.

**Procedimento de ensaio proposto:** parar um serviço de laboratório de forma limpa, copiar dados/configuração/histórico com hashes, carregar em segundo diretório isolado na mesma versão, verificar contadores/flags/listas/clientes/tipos, e decodificar um ticket emitido antes da cópia. Testar também ausência da chave, arquivos truncados, restauração de filas e reinício inesperado. Não usar dados/chaves reais em fixtures de teste. Não chamar `Peer.store()` numa análise presumidamente offline sem contenção: ele chama `sendHeloToAll()` antes de gravar (`core/Peer.java:1002`).

`had-antispam-backup` e `had-antispam-restore` estão instalados na VM pela release 1.1.9. Um backup operacional de 39 arquivos foi criado, teve checksum validado e passou `--dry-run`. O restore com JAR upstream e estado sintético também passou em laboratório isolado, incluindo `server.key`, `client.map`, CIDR e dicionário. Cópia para destino separado, restore entre hosts/releases, compatibilidade de serialização Java e RPO/RTO continuam **NÃO CONFIRMADOS**. Detalhes em [BACKUP-RESTORE.md](BACKUP-RESTORE.md).

## 9. Testes reproduzíveis a acrescentar/relacionar

Executar em diretório temporário com `data/` próprio, rede impedida, sem iniciar o daemon e sem chaves reais. Compilar contra o código do commit auditado; `dist/SPFBL.jar` sozinho não comprova correspondência com esse código. Estes são critérios esperados derivados dos métodos, não afirmações de teste executado neste documento.

| Caso | Ação e prova necessária |
|---|---|
| Binomial e duplicação | Criar Distribution; inserir H(t1), S(t2), reinserir S(t2); provar H=1,S=1,P=.5. Mover t2 para HAM e provar H=2,S=0. |
| Amostra mínima e limiares | Usar `getSpamProbability(null,8)` com 7/8 eventos; verificar null versus valor, caps .25/.50/.75 e operadores estritos em `getStatus`. |
| Limite/tempo | Inserir 257 timestamps ordenados e provar descarte do mais antigo; adicionar evento mais velho que 7 dias, chamar `dropExpiredQuery`, provar exclusão. |
| Moderno | Subclasse no pacote `net.spfbl.data` ou reflexão controlada para `add/refreshFlag`: provar primeira classificação só após N eventos, fórmulas das somas, flags negativas e recuperação com eventos positivos; testar restrição reserved. |
| Moderno e relógio | Avançar apenas TIME em fixture, sem novos eventos: provar que as somas não decaem; testar expiração e que leitura de flag atualiza last. |
| IPv6 | Processar dois IPv6 públicos distintos no mesmo /64 e observar mesma folha de reputação; outro /64 deve seguir outra folha. Capturar snapshot REP6, sem DNS/WHOIS real. |
| Sender autenticado | `data.SPF.addHarmful(sender,FAIL)` deve rejeitar enfileiramento; PASS aceita. Testar freemail separado por local-part e domínio não freemail. |
| P2P ponderado | Dois peers de laboratório com 33+ tokens comuns variados e 8+ amostras por token; provar correlação, teto e proporcionalidade; peer sem amostra comum não contribui. Não exercer envio real. |
| Ticket/feedback | PASS parcial no core 1.1.9 isolado: ticket de consulta PASS aceitou `SPAM` e, em seguida, `HAM` (`OK`/`OK`) usando a mesma chave, sem imprimir o valor. Permanecem testes de inválido, idade >5d, duplicação/fallback legado, associação `HEADER`/DATA e contadores/efeitos sem presumir flags imediatas. |
| Namespace | Usuários A/B com Recipient/Trap locais e fonte IP comum; provar isolamento das chaves locais e compartilhamento global do IP; verificar autorização nos listeners separadamente. |
| Spamtrap | Registrar trap (0), inexistente futuro e permanente; comparar respostas e flags; controlar aleatoriedade do bloqueio e verificar que `getTicket` não registra por si só SPAM. |
| Persistência | Processo A cria dados, snapshot, processo B carrega e compara estado; repetir sem chave e com truncamento. Só esse teste comprova restore, não mera existência de `load/store`. |

## 10. Divergências e decisões pendentes do escopo HAD

1. **Reputação uniforme:** contrariada. Binomial, flags, listas e sinais externos têm contratos distintos; dashboard/API devem preservar a origem e o tipo.
2. **Todos os peers com mesmo peso:** contrariada pela correlação e pelo teto por peer. Há limite de influência, mas nenhuma prova de robustez contra peers maliciosos ou Sybil só com essa fórmula.
3. **Reputação moderna compartilhada integralmente:** NÃO CONFIRMADA. O pacote REPUTATION compartilha binomial/frequência; efeitos Block são outro caminho.
4. **Feedback sempre atualiza todas as entidades:** contrariada pelos métodos diretos de reclamação/`Query.setSpam`; classificação de Query é fluxo adicional.
5. **Spamtrap sempre gera um SPAM P2P:** contrariada pelo caminho de envelope que aplica -1, ticket e bloqueio probabilístico. Propagação posterior completa exige ensaio.
6. **Reputação por ASN e IPv6 por endereço:** ASN NÃO CONFIRMADA; a árvore CIDR moderna para IPv6 termina no /64.
7. **Prioridade HAD local → público → DNSBL:** proposta futura. Não é a prioridade uniforme atual, que varia conforme método/filtro e inclui ponderação local de flags.
8. **Backup/restore operacional:** estrutura e utilitários HAD confirmados por código/testes; snapshot real e restore dry-run passaram, mas restauração real em host de staging e cópia externa ainda pendentes.

Antes de adaptar headers, feedback, isolamento ou persistência, preservar o formato de ticket, as estruturas originais e as regras de seleção de fonte. Uma UI pode explicar o comportamento atual sem modificar silenciosamente esses contratos.
