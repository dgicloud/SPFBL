# Monitor de conteúdo SpamFox com Bayes nativo

Os coletores cPanel/Exim e Postfix enviam ao gateway uma cópia após a fila. O gateway mantém a mensagem em RAM, consulta o classificador Bayes nativo do core SPFBL e registra somente estado, probabilidade, quantidade de atributos e latência. Essa observação não altera a entrega SMTP. Mensagens monitoradas não viram rótulos de treinamento automaticamente; o aprendizado supervisionado ocorre ao enviar `.eml` rotulado SPAM ou HAM no painel administrativo nativo.

## Instalar ou atualizar na VM central

Requisitos: Ubuntu 24.04, core SPFBL nativo ativo, Nginx funcional e `/etc/had-antispam/allowed-cpanels.txt` com os IPs públicos dos MTAs.

Instalação inicial:

```bash
cd /opt/spfbl
bash packaging/content-scan/install-gateway.sh --hostname matrix.example.com
```

Atualizar o gateway existente preservando os perfis de cliente:

```bash
cd /caminho/do/repositorio
bash packaging/content-scan/update-gateway.sh
```

O serviço escuta apenas em `127.0.0.1:11335`. O Nginx aceita `POST /internal/sfox/scan` somente dos IPs na allowlist e encaminha para `127.0.0.1:11335/v1/scan`. Os coletores não recebem credenciais por MTA; a admissão é feita pela origem IP, allowlist do Nginx e perfil local.

## Autorizar um MTA

O IP precisa constar na allowlist central e corresponder a um cliente `SPFBL` cadastrado no core. Crie um perfil do monitor e habilite a observação nativa:

```bash
had-content-scan-clients add --cidr IP_PUBLICO/32
had-content-scan-sync-allowlist
nginx -t && systemctl reload nginx
```

Perfis novos já habilitam a consulta Bayes nativa. Para perfis existentes:

```bash
had-content-scan-clients native-bayes PERFIL --enable
```

No ADMIN local do core, autorize o mesmo CIDR para pontuação passiva:

```bash
printf 'BAYES CLIENT ADD IP_PUBLICO/32\n' | nc 127.0.0.1 9875
```

`BAYES CLIENT ADD` só libera observação. A lista separada `BAYES DECISION` continua vazia por padrão; nenhum resultado do monitor altera decisões de entrega.

## Aprendizado e feedback

O Bayes nativo aprende apenas com mensagens `.eml` que recebem rótulo explícito no painel `/admin/bayes/` ou pelo comando administrativo `BAYES LEARN SPAM|HAM` após colocar os arquivos na pasta de aprendizagem. O gateway não transforma suas próprias previsões em rótulos. Com feedback habilitado no perfil, uma previsão SPAM de pelo menos 99,5% pode enviar `SPAM <ticket>` ao core, mas somente quando o ticket SPFBL é válido e coincide com a mensagem, a origem é pública e há exatamente um destinatário. Isso alimenta a reputação SPFBL; não altera o treinamento Bayes.

O gateway não persiste o `.eml`; a fila é limitada e fica em RAM. O log não inclui endereços, assunto ou corpo.

## Verificar operação

```bash
systemctl status had-content-scan-gateway
journalctl -u had-content-scan-gateway -f
journalctl -u had-content-scan-gateway --since '24 hours ago' --no-pager \
  | had-content-scan-report -
```

Em `scan_complete`, confira `engine=spfbl_native_bayes` e `native_bayes_status`. `spam` ou `ham` indica previsão confiante; `inconclusive` significa que o modelo ainda não tem evidência suficiente para o conteúdo; `not_allowed` indica que falta cadastrar o CIDR em `BAYES CLIENT SHOW`.
