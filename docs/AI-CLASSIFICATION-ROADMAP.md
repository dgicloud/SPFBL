# Classificação de spam com Jev e escala de concorrência

## Direção recomendada

Adicionar a análise Jev como um componente HAD opcional, fora do caminho e do protocolo do core SPFBL. O SPFBL continua fazendo SPF, reputação, P2P e decisões determinísticas como hoje. A primeira fase do classificador fica em modo sombra: registra a recomendação da IA para comparação, sem aceitar, rejeitar, atrasar ou alterar a reputação de mensagens.

**Escopo de dados decidido:** somente metadados técnicos. A integração não envia assunto, corpo, cabeçalhos, endereços, IPs ou domínios em claro; o contrato atual só aceita categorias e sinais booleanos enumerados.

## O que o código atual já fornece

- `Filterable.processFilter()` percorre uma ordem de regras e devolve o primeiro filtro aplicável. Os percentuais nos comentários de `Filterable.java` não são uma probabilidade calculada para cada mensagem e não servem diretamente como o limiar `X%`.
- O core combina sinais de envelope por `NeuralNetwork.getFlagEnvelope()`, mas essa operação entrega uma categoria `Flag`, não uma probabilidade calibrada de spam. O código tem métodos genéricos de backpropagation; não encontrei chamada de treinamento para o modelo estático de envelope.
- O cliente SPFBL instalado consulta principalmente dados do envelope. O hook HAD atualmente mantido neste repositório é MONITOR na ACL RCPT; ele não entrega corpo da mensagem ao core central.
- O filtro de conteúdo do servidor cPanel já passa pelo Exim/Imunify/Rspamd. Integrar IA após DATA exige um hook específico nesse estágio ou um módulo local do filtro; a simples alteração do core central não lhe dá acesso ao corpo.
- Jev oferece uma API de decisões tipadas (Choice, Score e Noul), com probabilidades e, conforme o tipo, confiança. A resposta é estruturada, mas a chamada ainda tem custo de entrada e requer chave de API no servidor. Jev não atualiza os pesos do SPFBL nem aprende automaticamente com os resultados.

## Como economizar chamadas

Não usar o comentário percentual das regras SPFBL como confiança. Criar um escore local explícito, treinado/calibrado com mensagens rotuladas por revisão humana ou feedback confiável. Para uma probabilidade local `p_spam`:

```text
p_spam <= T_ham       -> manter decisão local, não chamar Jev
p_spam >= T_spam      -> manter decisão local, não chamar Jev
T_ham < p_spam < T_spam -> encaminhar a Jev
```

Os limiares devem ser medidos em um conjunto rotulado próprio e escolhidos conforme o custo de falso positivo e falso negativo. Não há um `X%` universal. Até existir essa calibração, a primeira versão pode usar apenas categorias claramente determinísticas versus ambíguas como gate experimental, sem alegar que isso representa confiança estatística.

O protótipo exige confiança local explícita e não define um valor padrão. Sem confiança calculada, ele não chama o provedor. O core atual ainda não fornece essa probabilidade; a fonte do escore local e sua calibração são a próxima etapa necessária.

Uma chamada Jev deve classificar `ham`, `spam` ou `review` em uma única solicitação. Registrar probabilidades, confiança, versão do modelo, tokens/custo retornados, latência e resultado posterior da revisão. Repetições do mesmo conteúdo podem usar cache com HMAC e prazo limitado. A chave fica em variável de ambiente/arquivo secreto, nunca em fonte, logs ou no painel.

## Integração e segurança operacional

1. Construir um adaptador/gateway HAD separado do core, com limite de chamadas, timeout, circuit breaker e fila limitada.
2. Capturar a mensagem no estágio de conteúdo do cPanel somente após definir quais campos podem sair do servidor. Remover anexos, HTML ativo, endereços pessoais e outros dados que não forem necessários.
3. Executar primeiro em modo sombra e em poucos servidores. Timeout, indisponibilidade ou resposta inválida da IA não alteram o tratamento vigente pelo SPFBL, Imunify, Rspamd ou Exim.
4. Guardar apenas a representação mínima e os rótulos necessários para avaliação. Uma recomendação Jev sozinha não deve emitir `SPAM`/`HAM` no core nem propagar reputação P2P; isso permitiria envenenar decisões compartilhadas.
5. Medir cobertura do gate, custo total, precisão/recall, falsos positivos, latência p50/p95/p99 e diferença para as decisões atuais antes de habilitar qualquer ação.

## Virtual threads

O build atual mira bytecode Java 8 e a VM de produção estava em Java 17 no laudo operacional. Virtual threads tornaram-se recurso estável no JDK 21; portanto não podem ser adicionadas diretamente ao runtime atual sem uma atualização testada do JDK. O core SPFBL reaproveita objetos `Connection extends Thread` e limita slots por `spfbl_limit`; o bundle configura `spfbl_limit=127`. Migrar esse desenho para virtual threads exige trocar o modelo de workers reutilizáveis por uma tarefa por conexão e manter um limite explícito de concorrência/backpressure.

Virtual threads podem ajudar quando muitas tarefas ficam bloqueadas em I/O, como chamadas HTTP a Jev. Não tornam a execução de código CPU-bound mais rápida e não reduzem automaticamente latência. No ensaio existente, 1.000 QPS passou sem falhas com deadline de 3 s, enquanto testes de deadline estrito de 1 s tiveram resultados intermitentes e timeouts observados na fase `connect`; isso ainda não demonstra saturação dos workers SPFBL. Antes de migrar o listener principal, repetir o teste com limite de conexão, backlog e métricas de fila controlados. Um piloto isolado Java 21 no gateway de IA tem menor risco que converter o core.

## Próximos passos

1. Mapear quais sinais técnicos já existem no Exim/Imunify e quais podem ser reduzidos às categorias permitidas sem exportar identificadores.
2. Preparar e avaliar um conjunto histórico rotulado, com retenção e remoção de PII definidas.
3. Calibrar a confiança local e selecionar o intervalo que aciona Jev; até lá, nenhuma mensagem chama o provedor.
4. Completar o gateway com configuração desativada por padrão, mock local e teste de contrato da API Jev.
5. Conectar o gateway ao estágio DATA em um único cPanel de homologação, em modo sombra, e medir resultados antes de permitir qualquer ação.
6. Medir concorrência primeiro com o limite atual e isolar um piloto de virtual threads para as chamadas Jev antes de alterar o core.

## Protótipo local

`integrations/jev/jev_classifier.py` contém o gate, o contrato allowlist de metadados, o cliente da Decisions API, timeout configurável, máximo de chamadas concorrentes e resultados sempre consultivos. A falta de credencial, capacidade, timeout ou resposta válida mantém a decisão base inalterada. Ainda não há endpoint/gateway público, chamada real ao provedor, conexão com ACL Exim nem implantação na VM.

`python -m unittest discover -s integrations/jev -v` passou 9 testes, incluindo gate de confiança, ausência de chamada sem escore, payload sem dados pessoais, limite de concorrência e fallback sem alterar a decisão. Nenhuma chave Jev/OpenRouter foi usada.

## Referências

- Código: `src/net/spfbl/core/Filterable.java`, `src/net/spfbl/data/NeuralNetwork.java`, `src/net/spfbl/service/ServerSPFBL.java`, `integrations/cpanel/exim/acl-rcpt-monitor.conf`.
- Evidência de carga: `docs/evidence/vm-load-smoke-20261002.md`.
- API Jev: https://openrouter.ai/blog/insights/what-is-jev/
- Virtual threads JDK 21: https://docs.oracle.com/en/java/javase/21/core/virtual-threads.html
