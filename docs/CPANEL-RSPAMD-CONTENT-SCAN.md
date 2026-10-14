# Add-on leve Rspamd para cPanel/Exim

Este add-on contém o coletor Python, os hooks Exim e o instalador, além da licença/atribuições do projeto. Ele não leva o core SPFBL/Java, Rspamd, Redis ou bibliotecas externas. O gateway deve estar previamente instalado na VM por `packaging/content-scan/install-gateway.sh`; sem esse gateway o preflight falha sem alterar Exim.

## Pré-requisitos e preflight

Configure o transporte pelo WHM (não edite o arquivo gerado `/etc/exim.conf`): abra **Service Configuration → Exim Configuration Manager → Advanced Editor**. Na seção **CONFIG**, defina `system_filter_pipe_transport` como `had_sfox_content_pipe`. Na seção **TRANSPORTMIDDLE**, inclua o conteúdo de `integrations/cpanel/exim/transport-content-scan.conf` do pacote. Esse transporte dedicado usa comando estático, transfere metadados Exim em variáveis de ambiente codificadas em Base64 e usa o envelope BSMTP nativo para repassar todos os destinatários. O coletor remove a moldura BSMTP e o dot-stuffing antes do envio ao gateway. O filtro MONITOR continua analisando mensagens SMTP externas não autenticadas, inclusive submissões nas portas 465/587, e elas permanecem visíveis no histórico do Rspamd. A porta de entrada original é usada apenas como critério de aprendizado: no cPanel/Exim, somente mensagens recebidas na porta 25 são elegíveis ao Bayes e ao feedback SPFBL; 465/587 ou porta ausente continuam monitoradas, mas não treinam nem geram denúncia. Não passe remetente, destinatários, HELO ou IP como argumentos do processo, pois o Exim bloqueia esses valores de origem externa como tainted. Salve e confirme:

```bash
/usr/sbin/exim -bP system_filter_pipe_transport system_filter_user system_filter_group
```

Extraia o add-on e rode o preflight como root; ele não precisa de token nem altera o Exim. O teste exige as seis variáveis de metadados, incluindo a porta SMTP original, o sinalizador BSMTP e `use_bsmtp` no transporte carregado. O gateway falha fechado para o autotreino BSMTP quando essa porta não chega:

```bash
bash install-content-scan.sh --test-recipient caixa@seudominio.com.br --check
```

O preflight confirma transporte, usuário/grupo do filtro, TLS e se o IP já está liberado no gateway. Na VM central, cadastre o IP no core SPFBL e crie o perfil do monitor; o nome interno é gerado automaticamente:

```bash
had-content-scan-clients add --cidr IP_PUBLICO/32
had-content-scan-sync-allowlist
nginx -t && systemctl reload nginx
```

Então instale como root:

```bash
bash install-content-scan.sh --test-recipient caixa@seudominio.com.br
```

O instalador detecta o usuário e grupo configurados para o system filter, grava somente o endpoint e os limites em `/etc/had-content-scan/client.json`, cria o lock para o usuário do filtro e instala a ACL DATA gerenciada pelo cPanel. O argumento `--test-recipient` deve ser uma caixa local que o Exim roteia; o smoke usa SMTP sintético e não entrega mensagem. Antes do rebuild, testa a leitura da configuração e o acesso ao lock como essa mesma conta.

## O que acontece

Depois do aceite SMTP, o Exim fornece uma cópia `unseen` da mensagem ao cliente por `stdin`. Para entrada de um único destinatário, a ACL remove cabeçalhos de ticket fornecidos pelo remetente e encaminha ao coletor o `Received-SPFBL` da consulta nativa válida. O cabeçalho nativo permanece na mensagem normal entregue; o coletor remove sua cópia antes de pedir a análise Rspamd. Perfis novos habilitam o autotreino conservador do Bayes por padrão, sujeito à elegibilidade dos metadados e aos limiares do Rspamd. Separadamente, quando o score Rspamd é >= 15, há IP público, destinatário único e ticket SPFBL válido, o gateway pode enviar uma única denúncia `SPAM <ticket>` ao core. Essa chamada transmite somente o ticket nativo, não o corpo, assunto nem modelo Bayes. O mesmo recebimento já pode gerar análise, aprendizado e feedback: não é preciso aguardar uma segunda cópia da mensagem. A fila central é limitada a quatro mensagens além de dois workers e responde `202` antes da classificação. O Exim nunca recebe a decisão do Rspamd; falha, limite de 25 MiB ou lotação preserva a entrega original. O feedback só ocorre para perfis explicitamente habilitados e não modifica a entrega já aceita.

Na VM central, o autotreino e o feedback SPFBL são opções independentes por MTA. Perfis novos começam com autotreino ligado e feedback SPFBL desligado. A CLI `had-content-scan-clients` controla as opções por perfil; o estado de cada mensagem aparece no evento sanitizado `scan_complete` como `autolearn_profile_selected` e `spfbl_feedback`.

A VM guarda corpos somente em RAM e pode perder mensagens da fila durante reinício. O Rspamd processa no ambiente HAD; a classificação ocorre no Rspamd central da HAD, sem chamada a provedor externo. Para instalação, rollback e limites do piloto, consulte `README.md` do pacote.
