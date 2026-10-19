# Bayes nativo do SPFBL

O core mantém um classificador Bayes local para assunto e texto simples/HTML. O modelo guarda fingerprints SHA-256 das mensagens e hashes dos termos, não o arquivo `.eml` original. Anexos não participam da análise.

## Treinar pelo painel

Administradores autenticados podem abrir `https://matrix.example.com/admin/bayes/`. Usuários associados a um `CLIENT` autorizado podem abrir `https://matrix.example.com/account/bayes/`.

Envie mensagens `.eml` revisadas e escolha SPAM ou HAM. O modelo Bayes é global à instância: o rótulo enviado por um usuário pode afetar a classificação dos demais clientes conectados à mesma instância. A instância processa o arquivo em memória e descarta o conteúdo bruto após aprender.

O upload não rejeita mensagens em trânsito e não envia arquivos aos servidores de e-mail clientes. As integrações de envelope em `integrations/cpanel` e `integrations/postfix` não enviam corpo. O treinamento de conteúdo permanece uma ação explícita no painel.

Envie apenas exemplos revisados. Não rotule automaticamente usando a previsão do próprio Bayes, pois isso reforçaria os erros do modelo. Arquivos duplicados não são contados novamente e uma tentativa de reaproveitar o mesmo conteúdo com rótulo oposto é reportada como conflito.

## Clientes e permissões

No painel administrativo, cadastre o contato do cliente junto com o primeiro hostname e IP/CIDR; depois associe servidores adicionais ao cadastro. A operação corresponde a `CLIENT ADD <cidr> <hostname> <permissão> <email>`.

O treinamento pelo painel do cliente escreve no modelo global. O cadastro em `BAYES CLIENT` torna o MTA elegível para a inspeção de conteúdo via SPAMD; `BAYES DECISION` é a autorização explícita para rejeitar mensagens com probabilidade de SPAM igual ou superior a 0,995. O upload rotulado, por si só, não habilita decisões automáticas no MTA.

Uma decisão Bayes autorizada rejeita SPAM de alta confiança mesmo quando `ACTION RED` do cliente está em `FLAG`. Isso permite que a reputação continue apenas marcando mensagens suspeitas, enquanto o Bayes aprendido pode rejeitar conteúdo comprovadamente spam. Whitelists explícitas, mensagens já rejeitadas/bloqueadas e políticas de retenção (`HOLD`) mantêm prioridade. Resultados brandos que seriam apenas `FLAG` são avaliados pelo Bayes antes de o MTA aceitar a mensagem.

## Comandos ADMIN

Os comandos abaixo são locais ao servidor e usam o listener ADMIN TCP 9875. Mantenha-o restrito a loopback ou a uma rede administrativa confiável:

```sh
printf 'BAYES STATS\n' | ncat 127.0.0.1 9875
printf 'BAYES CLIENT SHOW\n' | ncat 127.0.0.1 9875
printf 'BAYES CLIENT ADD MTA_PUBLIC_IP/32\n' | ncat 127.0.0.1 9875
printf 'BAYES CLIENT DROP MTA_PUBLIC_IP/32\n' | ncat 127.0.0.1 9875
printf 'BAYES DECISION SHOW\n' | ncat 127.0.0.1 9875
printf 'BAYES DECISION ADD MTA_PUBLIC_IP/32\n' | ncat 127.0.0.1 9875
printf 'BAYES DECISION DROP MTA_PUBLIC_IP/32\n' | ncat 127.0.0.1 9875
printf 'BAYES ENABLE\n' | ncat 127.0.0.1 9875
printf 'BAYES DISABLE\n' | ncat 127.0.0.1 9875
```

Para habilitar o modelo são necessários exemplos mínimos de SPAM e HAM conforme informado pelo próprio comando `BAYES ENABLE`. Use conjuntos independentes para medir falsos positivos antes de permitir que Bayes participe de decisões de entrega.

## Limites da classificação

Uma consulta SPFBL de envelope não contém assunto ou corpo, portanto o Bayes de conteúdo não participa dessa consulta. O core também possui protocolo SPAMD para Exim e outros MTAs que optarem por análise de mensagem completa. O instalador legado `client/spamfox.cpanel.sh` e o DirectAdmin configuram esse fluxo para mensagens elegíveis; a integração modular cPanel e a integração Postfix deste repositório continuam somente com envelope.

No fluxo SPAMD, a mensagem pode ser gravada temporariamente em `incoming/` quando o core identifica a fila e o hostname. O processo interno remove arquivos com mais de sete dias. O administrador deve restringir TCP 9877 aos MTAs cadastrados e considerar essa retenção ao definir sua política de privacidade.

O modelo não é propagado pela rede P2P. Para replicar o aprendizado em outra instância, treine cada uma com o mesmo conjunto revisado.
