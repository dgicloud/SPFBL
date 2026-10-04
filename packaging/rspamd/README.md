# Rspamd e Redis locais para SpamFox

Este instalador adiciona Rspamd e Redis na VM Ubuntu 24.04 que hospeda o core SPFBL. O scanner HTTP (11333), o controller (11334) e Redis (6379) ficam presos ao loopback. Ele não altera SPFBL, Exim, Postfix, nftables ou portas públicas.

O Bayes usa Redis com schema novo, no mínimo 200 mensagens aprendidas por classe e sem autolearning. Apenas HAM/SPAM revisados por operador devem ser treinados. Redis tem teto de 512 MiB, `noeviction` para preservar os exemplos aprendidos, AOF e limites systemd; Rspamd fica limitado a 1 GiB e dois workers. O scanner recebe mensagens de até 25 MiB e tem limite de processamento de 12 segundos.

Execute como root em Ubuntu 24.04:

```bash
bash install-local.sh
```

O instalador consulta o repositório APT oficial assinado do Rspamd, salva cópias de arquivos tocados em `/var/backups/had-antispam/rspamd/` e recusa substituir configurações locais existentes que não estejam marcadas como gerenciadas pela HAD.

## Estado funcional e integração

Rspamd 4.2.1 e Redis estão ativos na VM `antispam.hadcloud.srv.br`; o gateway de conteúdo foi instalado no loopback, com rota HTTPS no Nginx limitada aos oito IPs allowlisted dos cPanels. Um e-mail sintético passou pelo gateway e foi classificado; o pedido fora da allowlist recebeu 403. Ainda não há um cPanel conectado ao fluxo de conteúdo. No Exim, o system filter `unseen pipe` entrega uma cópia já enfileirada ao coletor; ele envia blocos HTTPS autenticados à fila RAM. O gateway responde `202` ao concluir o enfileiramento e dois workers classificam depois no Rspamd local. A sessão SMTP não espera por essa análise; a entrega local pode esperar apenas o upload da cópia.

O fluxo de coleta não cria outro `.eml` em disco no cPanel, Nginx ou gateway. O cliente aceita até 25 MiB, serializa um upload por cPanel; Nginx desativa request buffering e gravação do corpo; a fila central tem quatro posições além dos dois workers. Filas e mensagens em análise ficam apenas em RAM, então indisponibilidade, lotação ou reinício podem descartar eventos MONITOR sem afetar a mensagem original. Rspamd recebe `Flags: no_log`, usa dois workers locais e mantém o Bayes sem autotreinamento. Nenhum corpo/assunto é enviado ao Jev/OpenRouter.

O controller fica em loopback, exige o segredo root-only para `/learnspam` e `/learnham` e recusa fontes `File`/`Shm`. `had-rspamd-learn` instala o fluxo de aprendizagem manual: operador, referência de revisão, classe e confirmação explícita são obrigatórios. Ele transmite o arquivo local diretamente ao controller, não guarda uma cópia da mensagem e registra apenas SHA-256, tamanho, rótulo, operador, referência e resultado. Use a pasta `/dev/shm` para a cópia temporária de treinamento e remova-a após a operação. Correções de classe exigem motivo categorizado; a cache Bayes do Rspamd cuida da reaprendizagem. Nunca treine automaticamente com a própria previsão.

Instale/valide a CLI na VM como root:

```bash
bash packaging/rspamd/install-learning-controls.sh
had-rspamd-learn stats
```

Para treinar somente uma mensagem revisada por operador:

```bash
had-rspamd-learn learn spam /dev/shm/reviewed.eml --reviewer carlos --reference CASE-1234 --confirm-reviewed
had-rspamd-learn learn ham /dev/shm/reviewed.eml --reviewer carlos --reference CASE-1235 --confirm-reviewed
```

O CLI recusa a mesma amostra repetida com o mesmo rótulo e exige `--correction-reason` (`reviewer_reclassified`, `verified_user_feedback`, `operator_label_error` ou `manual_retry_after_uncertain`) ao alterar/repetir um resultado registrado. A auditoria privada fica em `/var/lib/had-antispam/rspamd-learning/training.jsonl`. O Bayes só passa a pontuar após pelo menos 200 HAM e 200 SPAM; mantenha amostras revisadas e razoavelmente balanceadas. Os resultados não alteram SPFBL, reputação, P2P nem decisões do MTA.

Os testes unitários de contrato e fila passaram. Ainda falta instalar o add-on num cPanel de homologação e validar uma mensagem real sintética pelo hook Exim. Ainda não existe integração after-queue equivalente de Postfix, painel de resultados, quarentena/rejeição ou avaliação estatística holdout de falsos positivos/negativos.

Para o aprendizado inicial, reunir exemplos legítimos e spam revisados por operador, balanceados; só então treinar com os endpoints privilegiados do controller, usando segredo local root-only. O mínimo configurado é 200 HAM e 200 SPAM antes de considerar o símbolo Bayes útil. Não use classificações automáticas do próprio filtro como rótulos.
