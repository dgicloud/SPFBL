# Classificador Bayesiano nativo

O core SPFBL inclui um classificador Bayesiano local para o assunto e o texto simples/HTML da mensagem. Ele não consulta serviços externos, não envia o conteúdo para peers e não grava o arquivo EML: o modelo mantém somente fingerprints SHA-256 das mensagens e hashes SHA-256 dos termos.

O classificador só recebe exemplos com rótulo explícito. Não use a própria decisão do Bayes como rótulo automático, pois isso criaria um ciclo de reforço dos erros. Anexos são ignorados. O mesmo arquivo com conteúdo bruto idêntico não é contado duas vezes; tentar reaproveitá-lo com o rótulo oposto aparece como conflito.

### Corpus público para validação

Para reproduzir a validação offline com o corpus público do Rspamd, execute a partir da raiz do repositório:

~~~sh
python3 packaging/native/prepare-bayes-corpus.py --output /var/tmp/spfbl-bayes-rspamd-v1
~~~

O script confere o SHA-256 do arquivo fixado, extrai 300 exemplos SPAM e 700 HAM e separa um quinto de cada classe para teste. Os diretórios `train/` e `test/` ficam separados para evitar avaliar o modelo com as mesmas mensagens usadas no treino. O corpus e os EMLs extraídos não são incluídos no pacote nem no banco do modelo automaticamente.

Esse conjunto antigo serve para verificar a implementação e comparar versões; não representa o tráfego atual nem é suficiente para liberar rejeição automática. Colete HAM legítimo e SPAM confirmado do ambiente, sem misturar mensagens de teste no treino, e valide falsos positivos antes de habilitar o Bayes. O repositório `cw-l/email-corpus` contém mensagens de spam/phishing, mas não oferece uma classe HAM para esse treino supervisionado.

Para preparar esse conjunto como SPAM suplementar, fixe o commit e valide o arquivo com checksum:

~~~sh
python3 packaging/native/prepare-cwl-spam-corpus.py \
  --output /var/tmp/spfbl-bayes-cwl
~~~

O preparador extrai 1.429 EMLs rotulados como spam, scam ou phishing de duas submissões fixadas no repositório: 1.200 da submissão `cd73657af8d9165a` e 229 da submissão `b037056b02c300ba`. Ele separa 1.143 para treino e 286 para holdout, sem alterar o modelo. A origem não fornece HAM; também remove cabeçalhos de roteamento e defanga URLs. Use os exemplos junto a HAM confiável e separado. Não reative nem visite os links defangados. [Fonte e descrição do corpus](https://github.com/cw-l/email-corpus).

Na validação do modelo-base público (Rspamd Test Corpus v1.0 + cw-l), ele retornou probabilidade numérica para 312/346 mensagens SPAM e para 140/140 HAM. No limiar de 0,995, sinalizou 134 mensagens SPAM e 0 HAM; com 0,90 sinalizou 138 SPAM e 0 HAM; a 0,80 sinalizou 139 SPAM e 1 HAM. Uma avaliação separada com 183 exemplos da segunda submissão cw-l marcou 132/346 SPAM a 0,995, sem falsos positivos; esse lote ficou fora daquele modelo-base. Esses números não descrevem modelos treinados depois com corpora locais. O holdout público não basta para liberar rejeição automática; cada implantação precisa validar um conjunto independente e representativo de HAM e SPAM.

O dump Bayes do Rspamd foi acessado apenas para verificar disponibilidade (aprox. 5 MB), sem persistir cópia. Ele não é importado para o core: o Rspamd armazena estatísticas do classificador usando OSB (bigramas esparsos) e hashes próprios, incompatíveis com o extrator do Bayes nativo. Para uma semente compatível, use mensagens EML com rótulos conhecidos e treine pelo comando `BAYES LEARN`.

## Preparar exemplos

No diretório de trabalho do SPFBL, crie estas pastas e coloque mensagens EML revisadas nas categorias correspondentes:

~~~sh
install -d -m 0700 learn/spam learn/ham learn/test
~~~

O treinamento aceita até 2.000 arquivos por execução, cada um com até 5 MiB, e limita o lote a 128 MiB. Arquivos inválidos, duplicados ou com rótulo conflitante são reportados no resultado.

## Administrar

### Painel web do administrador

Administradores autenticados podem abrir https://spfbl.example/admin/bayes/ ou usar o atalho “Administração Bayes” no painel de e-mails. A tela mostra saúde do core, estado e persistência do modelo, contagem SPAM/HAM, vocabulário, CIDRs autorizados para pontuação e clientes autorizados a influenciar decisões.

Na área “Treinar com arquivos .eml”, selecione SPAM ou HAM e envie até 10 arquivos por lote (5 MiB por arquivo, 20 MiB no total). O core processa os bytes em memória, atualiza `data/content-bayes.db` e descarta o conteúdo original; a tela informa se cada mensagem foi incluída, duplicada, conflitante ou não pôde ser aprendida. O formulário usa token de uso único contra CSRF. Upload exige HTTPS.

### Área do cliente e Bayes compartilhado

Um usuário web não administrador só pode abrir `https://spfbl.example/account/bayes/` quando seu e-mail estiver associado a pelo menos um cadastro `CLIENT` no core. O painel conta os eventos recentes da própria conta disponíveis no painel de e-mails (até os 1.024 registros recentes que o core retorna), agrupando aceitos, rejeitados, suspeitos, pendentes e outros status. O atalho “Indicadores e treinamento” aparece no painel de e-mails desses usuários. A lista de mensagens e os detalhes continuam disponíveis no painel normal do usuário.

O usuário autorizado pode enviar até 10 arquivos `.eml` por lote, com limite de 5 MiB por arquivo e 20 MiB por lote, e até 100 arquivos em uma janela móvel de 24 horas por conta. O rótulo escolhido treina imediatamente o modelo Bayes global daquela instância SPFBL. Portanto, exemplos de um cliente podem alterar classificações futuras de todos os clientes conectados à mesma instância. O modelo não é compartilhado automaticamente entre instâncias independentes. O core processa os bytes em memória e mantém fingerprints e hashes de termos, sem guardar a mensagem original; o log registra somente a conta, rótulo e quantidade processada. Envie apenas mensagens revisadas e rotuladas corretamente. A autorização é verificada novamente no GET e no POST a partir do e-mail proprietário cadastrado em `CLIENT`.

Na seção “Clientes e servidores de e-mail”, o administrador pode cadastrar o contato do cliente junto do primeiro hostname e IP/CIDR, e depois associar novos servidores a um cliente existente. A tela executa a mesma operação `CLIENT ADD <cidr> <hostname> <permissão> <email>` usada pela CLI e grava imediatamente `data/client.map`. As permissões disponíveis são `SPFBL`, `DNSBL` e `NONE`; use `SPFBL` para os MTAs que consultam o serviço de reputação. Quando ainda não existe conta web para o e-mail do cliente, o formulário também executa o equivalente a `USER ADD <email> <nome>`, persiste `data/user.map` e envia a configuração inicial pelo fluxo TOTP nativo do core, desde que o SMTP de saída esteja configurado. Se o usuário já existe, a senha e o TOTP atual não são redefinidos nem reenviados. O cadastro não autoriza automaticamente o CIDR a enviar pontuação Bayes ou a influenciar decisões de entrega: os escopos `BAYES CLIENT` e `BAYES DECISION` continuam separados. A tela lista também os registros existentes, inclusive os que ainda não têm e-mail associado.

O treinamento manual não ativa decisões de entrega. Treinamento por usuário e treinamento administrativo alteram o mesmo modelo global daquela instância, mas não alteram a permissão de pontuação ou a política de entrega dos clientes. A lista “Clientes com decisão de entrega ativa” mostra os CIDRs autorizados separadamente; a inclusão continua exigindo aprovação explícita pelo comando BAYES DECISION ADD.

### Comandos ADMIN

Os comandos abaixo são enviados ao serviço ADMIN local (TCP 9875). Em produção, mantenha essa porta acessível somente localmente ou por uma rede administrativa restrita:

~~~sh
printf 'BAYES STATS\n' | ncat 127.0.0.1 9875
printf 'BAYES CLIENT SHOW\n' | ncat 127.0.0.1 9875
printf 'BAYES CLIENT ADD MTA_PUBLIC_IP/32\n' | ncat 127.0.0.1 9875
printf 'BAYES CLIENT DROP MTA_PUBLIC_IP/32\n' | ncat 127.0.0.1 9875
printf 'BAYES DECISION SHOW\n' | ncat 127.0.0.1 9875
printf 'BAYES DECISION ADD MTA_PUBLIC_IP/32\n' | ncat 127.0.0.1 9875
printf 'BAYES DECISION DROP MTA_PUBLIC_IP/32\n' | ncat 127.0.0.1 9875
printf 'BAYES LEARN SPAM\n' | ncat 127.0.0.1 9875
printf 'BAYES LEARN HAM\n' | ncat 127.0.0.1 9875
printf 'BAYES TEST amostra.eml\n' | ncat 127.0.0.1 9875
printf 'BAYES ENABLE\n' | ncat 127.0.0.1 9875
printf 'BAYES DISABLE\n' | ncat 127.0.0.1 9875
~~~

BAYES TEST procura somente o nome informado em learn/test/. O teste pode ser executado antes de ativar o modelo; use mensagens de validação separadas dos arquivos de treino e confira os falsos positivos antes de ativar. Para ativá-lo são necessários pelo menos 25 exemplos SPAM e 25 HAM. A ativação fica persistida junto do modelo em data/content-bayes.db.

O modelo não toma decisões para nenhum cliente por padrão. `BAYES CLIENT ADD` autoriza somente a observação passiva do classificador. A lista `BAYES DECISION` é uma segunda autorização, separada, para permitir que Bayes participe do resultado SPAMD daquele MTA. Remover um CIDR com `BAYES CLIENT DROP` também limpa sua autorização de decisão; `BAYES DECISION DROP` interrompe só a influência no SPAMD e mantém a observação passiva.

## Efeito na decisão

Na integração SPAMD do core, o Bayes só participa quando as regras SPFBL existentes não produziram um filtro e o CIDR foi explicitamente autorizado por `BAYES DECISION ADD`. A pontuação do gateway, por si só, nunca muda a entrega. No SPAMD, Bayes só gera decisão para SPAM com probabilidade posterior de pelo menos 0.995; resultados ambíguos e mensagens classificadas como HAM preservam o resultado SPFBL. A ação segue a política RED já configurada para o cliente: FLAG, HOLD ou REJECT. A classificação Bayesiana não cria banimento, reputação negativa ou anúncio P2P.

Uma consulta SPF de envelope não contém o corpo da mensagem e, por isso, não pode usar Bayes. O MTA precisa encaminhar a mensagem completa ao endpoint SPAMD do core antes da ação que deseja influenciar.

O gateway de conteúdo recebe cópias após a fila e consulta o Bayes nativo pelo protocolo interno do core em loopback. A observação é ativada por perfil (`native_bayes_enabled`) e preserva o IP do MTA validado pela allowlist. O core exige que esse IP corresponda a um cliente SPFBL e a um CIDR listado com `BAYES CLIENT ADD`. Esse acesso libera somente a pontuação passiva. O resultado contém decisão, probabilidade e quantidade de atributos; não altera entrega nem usa previsões como novos rótulos. Para que mensagens enviadas pela integração SPAMD possam ser influenciadas, é necessário também cadastrar explicitamente o CIDR com `BAYES DECISION ADD`.

Para ativar em um perfil de homologação já cadastrado no gateway:

~~~sh
had-content-scan-clients native-bayes PERFIL_HOMOLOGACAO --enable
~~~

O monitor não substitui treinamento rotulado: importe amostras HAM/SPAM revisadas com `BAYES LEARN` e avalie previsões do tráfego em uma janela separada antes de considerar uma política de bloqueio.

O classificador é local à instância. Para compartilhar exemplos entre servidores, importe o mesmo corpus revisado em cada instância; o modelo e os rótulos não são propagados pela rede SPFBL.
