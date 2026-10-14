# Piloto de conteúdo e autotreino automático

O SPFBL continua responsável por reputação SMTP. Os coletores assíncronos enviam cópias reais ao Rspamd central para análise e autotreino Bayes nativo; as decisões continuam em MONITOR e não alteram entregas. Não há revisão humana obrigatória por mensagem. As etapas abaixo sobre corpus revisado, validação e canário são documentação histórica de avaliação da camada de enforcement, não pré-requisitos para o autotreino automático.

## Corpus opcional para avaliação offline

O corpus de avaliação offline é opcional e serve para medir precisão antes de considerar ações de enforcement. Ele não é uma fila de revisão do tráfego dos monitores e não bloqueia o autotreino. Mensagens sintéticas de ensaio não medem precisão. Se a equipe optar por construir um holdout independente, use exemplos HAM/SPAM com rótulos conhecidos dos dois ambientes:

```text
/root/spamfox-reviewed/
  grupoguedes/ham/*.eml
  grupoguedes/spam/*.eml
  enhance/ham/*.eml
  enhance/spam/*.eml
```

As pastas são uma entrada manual privada, não um arquivo criado pelos monitores. O histórico nativo guarda metadados; o corpo das cópias é descartado após análise. Exportar os `.eml` originais das caixas com autorização e revisão. Não rotular usando o score do próprio filtro. Manter os arquivos de avaliação em armazenamento privado; não enviá-los a serviços externos.

Para medir campanhas novas sem vazamento entre treino e holdout, salvar ao lado de cada `.eml` um `.json` de mesmo nome base com `campaign_group`, atribuído pelo revisor a mensagens da mesma campanha. Exemplo: `{"campaign_group":"campanha-outubro-01"}`. O valor deve ser um identificador seguro, sem remetente ou assunto. O preparador mantém o grupo inteiro num único lado da divisão e guarda apenas o hash do identificador no manifesto. Se houver envelope MTA confiável, usar `{"campaign_group":"campanha-outubro-01","context":{"ip":"198.51.100.10","helo":"mx.example","mail_from":"","rcpt":["destino@example.com"]}}` e `--trusted-envelope`. Não reconstruir origem a partir de um `Received` arbitrário. Sem grupo informado, a mensagem vira grupo individual e o gate de qualidade bloqueia a ativação.

Preparação opcional offline, Python 3.9+, sem serviço ou aprendizagem:

```bash
umask 077
python3 tools/rspamd_corpus.py prepare \
  --input /root/spamfox-reviewed \
  --output /root/spamfox-corpus-v1 \
  --reviewer operador-revisor --reviewed --trusted-envelope
```

A ferramenta recusa saída existente, symlinks, rótulos contraditórios e limites excedidos. Remove duplicatas por conteúdo MIME decodificado, exclui GTUBE e reserva aproximadamente 20% de cada classe por grupo de campanha, mantendo mensagens do mesmo grupo juntas. Identificadores no manifesto não contêm assunto, endereços ou nomes originais. Arquivos `.eml` e envelopes continuam sendo dados privados: diretórios 700, arquivos 600. Toda mensagem precisa de grupo atribuído para que a avaliação passe o gate; a separação por hash sozinha não detecta campanhas semanticamente semelhantes.

Para avaliação offline, mantenha `holdout/` fora do aprendizado e use a WebUI ou o `rspamc` nativo apenas se decidir realizar um bootstrap manual. O fluxo contínuo dos monitores usa autotreino nativo automatizado; não instala daemon nem CLI de treino HAD. O mínimo 200 por classe habilita Bayes, mas não comprova precisão.

## Medir e decidir se o piloto está pronto

Depois do treino, na VM central e sem aprendizagem concorrente:

```bash
python3 tools/rspamd_corpus.py evaluate \
  --corpus /root/spamfox-corpus-v1 \
  --report /root/spamfox-evaluation-v1.json \
  --controller-secret-file /etc/had-antispam/rspamd-controller.secret
python3 tools/rspamd_corpus.py gate \
  --report /root/spamfox-evaluation-v1.json \
  --policy packaging/rspamd/pilot-quality-policy.json --mode mark --live-check
```

`evaluate` consulta somente holdout por `/checkv2` local com `Flags: no_log`; não treina e não publica os exemplos no histórico. Confere configuração, autolearn desativado e contadores antes/depois. O relatório separa projeções de marcação e retenção, falsos positivos, recall, intervalos de Wilson de 95%, cobertura Bayes/contexto SMTP e latência, também por origem. Score não é percentual de certeza.

A política inicial exige 200 exemplos treinados por classe, cobertura Bayes >=90%, contexto confiável em todas as amostras e relatório de até 72 horas. Para marcação exige holdout de 200 HAM/100 SPAM, limite superior de falsos positivos <=2% e limite inferior de recall >=80%. Para quarentena exige 400 HAM/200 SPAM, <=1% e >=85%. Também há critérios por servidor e latência p95 <=3s, máxima <=12s. Estes limites são política operacional inicial, não garantia universal de qualidade.

Com a divisão padrão de 20% do preparador, a quantidade mínima de exemplos MIME únicos revisados é aproximadamente 1.000 HAM e 500 SPAM para o gate de marcação; para quarentena, 2.000 HAM e 1.000 SPAM. Além dos totais, cada origem exigida (`enhance` e `grupoguedes`) precisa contribuir pelo menos 50 HAM/25 SPAM no holdout para marcação, ou 100 HAM/50 SPAM para quarentena. Distribuir os exemplos entre as duas origens e revisar campanhas semelhantes antes da separação; duplicatas removidas podem exigir mais arquivos de entrada.

`gate` não instala nem ativa nada. `--live-check` compara modelo/configuração atuais com o relatório na VM; se houve treino ou alteração, recusa o resultado e é necessário reavaliar. A impressão digital inclui toda a configuração efetiva e arquivos locais de regras/configuração, sem publicar valores ou segredos. Mapas externos e DNS podem mudar fora desse snapshot; revisar também disponibilidade e validade dos dados externos no período de avaliação. Uma avaliação válida não substitui teste de falha, revisão da caixa piloto e rollback. Enquanto faltar o conjunto revisado, não existe evidência de precisão nem autorização técnica para aplicar quarentena geral.

## Integrações candidatas

Exim usa `integrations/cpanel/exim/acl-data-spamfox-native-pilot.conf`: scanner nativo, uma caixa aprovada, remetente externo não autenticado, até 25 MiB, timeout de 12s, `defer_ok`. A variável `acl_m_sfox_canary` deve ser definida no RCPT para a caixa escolhida; `SPAMFOX_PILOT_MODE` define `mark` ou `quarantine`. O endereço dinâmico de `spamd_address` seleciona o túnel central apenas durante `acl_m_sfox_scan=yes`, preservando exatamente o endereço anterior na outra condição. O seletor é restaurado mesmo em falha. Modo mark acrescenta cabeçalhos; modo quarantine congela apenas a mensagem piloto na fila nativa, sem rejeitar/discardar pelo módulo central.

Grupo Guedes já tem SpamAssassin e ACLs Rspamd do ImunifyEmail. Não substituir sua configuração global nem remover ACLs do fornecedor. A reinjeção Imunify (`received_protocol=spam-scanner`) e sessões autenticadas ficam fora do ACL candidato, para evitar uma segunda análise/retenção do mesmo fluxo. Esses filtros continuam podendo rejeitar por suas próprias regras. O retorno central é uma camada adicional.

Postfix usa um worker-proxy adicional, privado, em `worker-proxy.inc`, com perfil `spamfox_mark` ou `spamfox_quarantine` de `settings.inc`. O proxy central usa `127.0.0.1:11336`, separado do gateway HTTP assíncrono em `11335`; o endpoint Postfix do stunnel encaminha para `11336`. Os workers TCP do scanner desabilitam entradas `File`/SHM, pois recebem o corpo MIME diretamente. Em `mark`, toda transação SMTP externa com exatamente um destinatário recebe somente marcação: uma ação terminal original, como `reject`, é preservada em `X-SpamFox-Result`, mas a transação é aceita para que a cópia after-queue preserve o ticket SPFBL e possa gerar a denúncia nativa de alta confiança. `quarantine` continua limitada à caixa canário explicitamente aprovada. No Enhance, o encadeamento SMTP deve ser Rspamd local, SRS, OpenDKIM e, por último, SpamFox. Postfix envia aos milters na ordem configurada; uma ação terminal pode impedir os seguintes ([documentação oficial MILTER_README](https://www.postfix.org/MILTER_README.html)).

O Enhance atualmente define `non_smtpd_milters = $smtpd_milters`. O coletor after-queue reinjeta pelo `sendmail -G -i`, caminho que o Postfix processa como mensagem não-SMTP e que usa `non_smtpd_milters` ([documentação oficial](https://www.postfix.org/MILTER_README.html); [fluxo after-queue](https://www.postfix.org/FILTER_README.html)). O candidato deve ser anexado somente como override `-o smtpd_milters=...` no serviço `smtp/inet` de entrada da porta 25 no `master.cf`, depois de Rspamd local, SRS e OpenDKIM. Não acrescente o endpoint à lista global: assim as portas autenticadas 587/465 e a reinjeção after-queue continuam usando apenas os filtros existentes. Um teste composto isolado no Enhance executou o filtro after-queue instalado, a cadeia local real e o candidato apenas no serviço SMTP; reinjetou uma mensagem sintética por fila descartável e entregou somente ao sink SMTP em memória no loopback. Os cabeçalhos SpamFox confiáveis sobreviveram à reinjeção, valores forjados foram removidos e os hashes de `main.cf`/`master.cf` de produção ficaram idênticos. A evidência de 19:19 UTC registra que os contadores não mudaram naquela rodada. Em leituras posteriores, o total local de mensagens aprendidas passou de 26.994 para 27.005 (BAYES_SPAM 156.604→156.612; BAYES_HAM 17.872→17.875), sem origem comprovada. Em 05/10, normalizamos `/etc/rspamd/override.d/classifier-bayes.conf` para conter somente `autolearn = false;`, após salvar backup; `configtest` e `configdump -j` passaram, e Rspamd foi recarregado ativo. O contador mudou mais uma unidade entre as leituras imediatas, então estabilidade ainda precisa ser medida. A última rechecagem SSH, em 07/10, não obteve banner; essa configuração não foi confirmada novamente depois de 05/10. Evidências: `docs/evidence/rspamd-postfix-afterqueue-composed-smoke-20261005.json`, `docs/evidence/rspamd-postfix-real-milter-chain-smoke-20261005.json` e `docs/evidence/rspamd-postfix-reinjection-scope-smoke-20261005.json`. O smoke composto valida marcação com mensagem sintética; não mede precisão.

Não adicionar regra de remoção SpamFox ao `header_checks` global: o Postfix reaplica a verificação no `cleanup` durante a reinjeção after-queue, o que apagaria os cabeçalhos confiáveis já acrescentados pelo piloto. `smtpd_header_checks` não existe no Postfix 3.8.6 do Enhance (`postconf -d` o retorna como parâmetro desconhecido). Para o único destinatário canário, `spamfox_pilot.lua` remove os valores recebidos e acrescenta o resultado novo na resposta Milter; a reinjeção local não inclui o proxy candidato. Manter `milter_default_action=accept`.

O ensaio no Enhance comprovou `SMFIR_QUARANTINE` na fila nativa isolada, remoção do resultado forjado, liberação individual por `postsuper -H`, aceite com scanner desligado e ausência de retenção para outra caixa/múltiplos destinatários. O ensaio posterior encadeou os milters reais locais antes do scanner SFOX temporário, verificou que outro serviço sem override não chamou o candidato e simulou a reinjeção `sendmail -G -i`: os três filtros não-SMTP locais rodaram e o candidato SFOX foi ignorado. O smoke composto after-queue em modo mark também passou em fila isolada. A quarentena composta com o coletor e liberação individual passou em 07/10, conforme `docs/evidence/rspamd-postfix-afterqueue-quarantine-smoke-20261007.json`. O bypass por macro Milter de autenticação passou nos dois modos; isso não comprova uma sessão SASL real. Ainda faltam submission autenticada real e o túnel mTLS central. Os testes usaram mensagens sintéticas isoladas e não medem precisão.

Os modelos do Rspamd local do Enhance e do central são distintos. Volume aprendido localmente não comprova os rótulos do modelo central e não deve ser copiado sem revisar a origem.

Os templates stunnel usam mTLS, uma CA exclusiva para piloto e certificados individuais. Portas candidatas centrais 11933 (Exim) e 11932 (Postfix), restritas aos IPs inscritos; endpoints locais presos ao loopback. O binary stunnel4 nativo foi instalado na VM para validar os templates; serviço/target estão desabilitados e inativos até haver certificados e seleção explícita de MTA. O teste de loopback passou em 12 casos: certificado de cliente aceito, sem certificado/CA estrangeira/uso incompatível recusados em ambos endpoints; clientes aceitaram o servidor com hostname correto e recusaram hostname errado. As chaves/certificados de teste foram efêmeros em RAM e apagados; o backend foi um echo isolado, não Rspamd. Evidência: `docs/evidence/rspamd-stunnel-mtls-smoke-20261005.json`.

O instalador local `packaging/rspamd/install-local.sh` grava `allow_file_and_shm_inputs = false`, pois o protocolo não deve permitir leitura de caminhos locais fornecidos pelo cliente. Antes de expor o scanner, confirmar esse valor efetivo com `rspamadm configdump` na VM central; o arquivo do instalador não prova o estado ativo. Acesso HTTPS da WebUI, ADMIN SPFBL e Redis não fazem parte desses túneis. Nenhuma porta pública foi aberta nem certificados de MTA instalados.

## Implantação gradual e reversão

1. Registrar caixa/servidor, versão, hashes das configurações existentes e resultado de qualidade. Salvar cópias privadas do Exim/Postfix/Rspamd/stunnel antes de tocar arquivos.
2. Testar em configuração isolada a aceitação normal, marcação, retenção e scanner indisponível. Testar também múltiplos destinatários, autenticados, mensagem grande e cabeçalho forjado. No Postfix, a marcação composta com after-queue passou em mensagem sintética entregue somente ao sink em memória. Quarentena e liberação individual também passaram combinadas com o coletor em 07/10; falta validar submission autenticada real.
3. Para avaliar enforcement, habilitar mark somente na caixa aprovada e observar tráfego real e tempos. Os monitores permanecem ativos. A política de enforcement é independente do autotreino, que pode continuar automático nas faixas conservadoras.
4. Passar para quarantine somente com nova avaliação aprovada e observação satisfatória. Retenção deve permitir inspeção/liberação, sem exclusão automática.
5. Em regressão, retirar apenas a seleção do piloto, restaurar o snapshot da configuração correspondente, validar sintaxe e aplicar o reload/rebuild nativo. Não limpar filas. Identificar os IDs retidos pelo piloto e liberar individualmente após revisão (`exim -Mt ID` ou `postsuper -H ID`, conforme o MTA); não liberar todas as mensagens congeladas/hold indiscriminadamente.

Os testes de preparação estão em `docs/evidence/rspamd-supervised-pilot-preparation-20261005.md`. O estado real dos monitores, o treino Bayes central e o relatório agregado de 24 horas estão em `docs/evidence/rspamd-live-monitor-report-20261005.md`. A pasta de revisão `/root/spamfox-reviewed` estava vazia no snapshot de 05/10. Filas nativas isoladas Exim/Postfix, liberação individual, cadeia real de milters Postfix, smoke composto after-queue em marcação e templates mTLS em loopback foram testados. Esse registro é histórico: corpus rotulado manualmente não é requisito do autotreino operacional. Precisão e comportamento de enforcement continuam sendo avaliados separadamente antes de ampliar `mark` ou habilitar quarentena. A caixa selecionada no sp01 é `teste@facelookcosmeticos.com.br`; a existência foi confirmada por `doveadm user` em 07/10.


## Atualização de validação em 07/10

As pendências históricas de transporte e autenticação isolada acima tiveram novos ensaios: mTLS entre sp01 e central passou para HTTP nativo e Milter com worker sintético separado; autenticação SMTP AUTH real passou em Postfix/Dovecot descartáveis, nos dois modos, junto ao coletor after-queue instalado. Reversão isolada com check/reload passou. Consulte `docs/evidence/rspamd-sp01-canary-selection-20261007.md` e seus JSONs. Esses ensaios não ativaram o canário nem mediram precisão. A revisão humana não é necessária para o autotreino Bayes; a avaliação antes de ampliar ações de `mark` ou habilitar quarentena é um controle separado de enforcement. A origem do aprendizado deve continuar restrita aos coletores inscritos.

## Implantação MVP em mark — 08/10/2026

Esta seção registra o estado mais recente e prevalece sobre as anotações de preparação de 05–07/10 acima.

O piloto foi ativado nas configurações de produção para somente duas caixas, sempre em `mark`:

| Ambiente | Caixa canário | Caminho de análise |
|---|---|---|
| sp01 / Postfix | `teste@facelookcosmeticos.com.br` | Apenas serviço SMTP de entrada `smtp/inet` na porta 25; Milter local `127.0.0.1:21336`, túnel mTLS central `11932`. Submissions autenticadas e o filtro after-queue existente mantêm os caminhos anteriores. |
| Grupo Guedes / cPanel Exim | `contato@setaigrupogp.com.br` | ACL RCPT limita a caixa; ACL DATA chama o scanner central via `127.0.0.1:21333` e túnel mTLS `11933`. Só remetente externo não autenticado, um destinatário, até 25 MiB; reinjeção `spam-scanner` fica fora. |

No servidor central `151.242.41.35`, os listeners do piloto estão ativos, os dois processos de transporte mTLS estão ativos e o Rspamd 4.2.1 está ativo. A seleção central usa `spamfox_mark`; a allowlist contém somente as duas caixas acima. O nível global de log segue `notice`. O módulo local `packaging/rspamd/pilot/spamfox_pilot.lua` agora registra decisões nesse nível para que a revisão funcione sem aumentar o volume de logs global. A cópia anterior está preservada em `/etc/spamfox-pilot/spamfox_pilot.lua.before-20261008` com modo 600.

Validação após esse ajuste: `rspamadm configtest` passou e o serviço recarregou ativo. O ensaio Milter real pelo túnel mTLS passou os três casos: canário marcado; tentativa de ação de quarentena continuou sem reter mensagem; destinatário fora da allowlist não recebeu cabeçalhos do piloto. O ensaio Exim usou o scanner central ativo e uma fila descartável em RAM: uma mensagem canário foi aceita e enfileirada somente no spool temporário, cabeçalhos forjados foram removidos, o seletor foi restaurado e a mensagem não foi entregue. Os relatórios estão em `docs/evidence/rspamd-mvp-sp01-active-check-20261007.json` e `docs/evidence/rspamd-mvp-grupoguedes-active-check-20261007.json`.

O log central confirmou dois eventos do smoke sintético após a mudança para `notice`; exemplo: `SpamFox MVP mode=mark result=add header action=add header score=7.80`. Esse score é de uma mensagem sintética e não mede eficácia. Nos logs de Exim atualmente legíveis, há 704 eventos históricos `HAD AntiSpam MONITOR` e zero eventos de ação do piloto. Portanto, a configuração está ativa e os caminhos testados respondem, mas ainda não há uma mensagem natural observada em nenhuma caixa canário. A etapa de observação real começa quando uma mensagem externa chegar a uma dessas caixas.

Os serviços `postfix`, `rspamd` e o transporte mTLS estão ativos no sp01; `exim`, `had-antispam-client` (modo MONITOR) e o transporte mTLS estão ativos no Grupo Guedes. O filtro after-queue preexistente do Postfix e o monitor SPFBL do Exim foram mantidos. No sp01, a configuração consultada não lista `had-antispam-client.service`; não contar esse unit como monitor ativo. As reversões locais continuam prontas: dry-run indica 1 arquivo no Postfix e 5 arquivos no Exim, sem aplicar restauração.

O piloto de conteúdo adiciona cabeçalhos `X-SpamFox-*` nas caixas selecionadas; não rejeita nem coloca mensagens reais em quarentena, não substitui o core SPFBL e não altera outras caixas. O autotreino Bayes é separado e automático para os clientes inscritos, usando apenas mensagens com metadados SMTP completos e scores extremos; não exige que alguém aprove cada e-mail. Precisão, falsos positivos e segurança de quarentena ainda não foram medidos; a ação `quarantine` segue desativada.

## Autotreino automático dos coletores — 08/10/2026

O gateway central agora tem autotreino habilitado para os clientes `enhance-postfix` (sp01) e `grupoguedes-content`. A ativação preservou credenciais e allowlists e foi precedida por cópia da configuração em `/var/backups/had-antispam/rspamd/clients-before-autolearn-20261008T210801Z.json`. O cliente de piloto de timing permanece desativado. Não há etapa de aprovação humana por mensagem.

O Rspamd nativo só aprende mensagens do perfil dedicado com ID de fila, remetente, destinatário, IP e HELO válidos, e exclui SMTP autenticado. Os limites atuais são score de spam >= 15 e ham <= -2, com balanceamento entre classes e `min_learns = 200`; mensagens intermediárias são analisadas, mas não treinam. `rspamadm configtest` passou e `rspamd` e `had-content-scan-gateway` estão ativos.

Após a ativação, duas análises reais do sp01 registraram `smtp_metadata_complete=true` e `autolearn_profile_selected=true`, com scores -1,20 e 1,17. Elas não cruzaram os limites e, corretamente, não foram aprendidas. O último evento do Grupo Guedes consultado é anterior à ativação; ainda não há confirmação de uma mensagem posterior nem de um evento real de aprendizado desse cliente. Um teste sintético local ao `/checkv2`, sem `Settings-ID`, retornou HTTP 200 e reconheceu o destinatário, sem selecionar perfil de treino. A próxima verificação deve confirmar eventos naturais de cada MTA e o primeiro aprendizado nativo; não se deve contar a seleção do perfil como prova de que uma mensagem já foi aprendida.
