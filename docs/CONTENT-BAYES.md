# Bayes nativo do SPFBL

O core mantém um classificador Bayes local para assunto e texto simples/HTML. O modelo guarda fingerprints SHA-256 das mensagens e hashes dos termos, não o arquivo `.eml` original. Anexos não participam da análise.

## Treinar pelo painel

Administradores autenticados podem abrir `https://matrix.example.com/admin/bayes/`. Usuários associados a um `CLIENT` autorizado podem abrir `https://matrix.example.com/account/bayes/`.

Envie mensagens `.eml` revisadas e escolha SPAM ou HAM. O modelo Bayes é global à instância: o rótulo enviado por um usuário pode afetar a classificação dos demais clientes conectados à mesma instância. A instância processa o arquivo em memória e descarta o conteúdo bruto após aprender.

O upload não rejeita mensagens em trânsito e não envia arquivos aos servidores de e-mail clientes. As instalações cPanel e Postfix consultam o envelope SPFBL; o treinamento de conteúdo permanece uma ação explícita no painel.

Envie apenas exemplos revisados. Não rotule automaticamente usando a previsão do próprio Bayes, pois isso reforçaria os erros do modelo. Arquivos duplicados não são contados novamente e uma tentativa de reaproveitar o mesmo conteúdo com rótulo oposto é reportada como conflito.

## Clientes e permissões

No painel administrativo, cadastre o contato do cliente junto com o primeiro hostname e IP/CIDR; depois associe servidores adicionais ao cadastro. A operação corresponde a `CLIENT ADD <cidr> <hostname> <permissão> <email>`.

O treinamento pelo painel do cliente escreve no modelo global. A autorização para enviar pontuação Bayes e a autorização para deixar o Bayes influenciar uma decisão SPFBL são controles separados. O upload rotulado, por si só, não habilita decisões automáticas no MTA.

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

Uma consulta SPFBL de envelope não contém assunto ou corpo, portanto o Bayes de conteúdo não participa dessa consulta. O core também possui protocolo SPAMD para quem decidir integrar a análise de mensagem completa. Essa integração exige configuração explícita no MTA e autorização de decisão; os instaladores de cPanel e Postfix deste repositório não enviam `.eml` automaticamente.

O modelo não é propagado pela rede P2P. Para replicar o aprendizado em outra instância, treine cada uma com o mesmo conjunto revisado.
