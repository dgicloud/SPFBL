# Observabilidade local

O pacote instala `spamfox status` e a unit `spamfox-observability.service`. O comando consulta a versão do core e resume a atividade P2P sem exibir hostnames, IPs ou e-mails. Uma falha de consulta peer aparece como indisponibilidade desse resumo, sem derrubar o status do core.

```bash
spamfox status
curl --fail http://127.0.0.1:9911/health
curl --fail http://127.0.0.1:9911/metrics
systemctl status spamfox-observability.service
```

O servidor HTTP fica vinculado somente a `127.0.0.1:9911`; mantenha essa porta fora do Nginx e do firewall externo. `/health` responde HTTP 200 quando o core está ativo e `VERSION` responde pelo ADMIN local; em falha responde HTTP 503. `/metrics` publica gauges Prometheus do core, consulta ADMIN, timer de persistência, resumo P2P e processo Java. Identidades de peers não são exportadas.

## Consultas por servidor no admin

O painel `/admin/bayes/` mostra **Total de requests TCP**, **Total de consultas de reputação** e uma tabela por hostname e IP/CIDR cadastrado, com cliente associado e última atividade. Os totais correspondem aos servidores atualmente cadastrados. Servidores do mesmo cliente são contados separadamente pelo CIDR. A seção é exclusiva do administrador e usa o fuso da conta autenticada.

Requests são solicitações não vazias atendidas de clientes identificados no listener SPFBL TCP/TLS. Incluem VERSION, feedback e outros comandos. Consultas de reputação são comandos SPF, CHECK e o formato legado por IP despachados para análise e verificações RCPT do protocolo Postfix. DATA, DNSBL/UDP, tráfego HTTP, conexões vazias e IPs não cadastrados não incrementam esse segundo contador. Tentativas repetidas contam novamente; os números não representam e-mails únicos nem comprovam entrega na caixa postal.

A coleta começa quando esta versão é ativada; logs históricos não são reconstruídos. Os contadores aparecem em memória ao concluir cada request, são atualizados na página ao abrir/recarregar ou clicar em **Atualizar**, e ficam em `data/client-request-metrics.json` dentro do estado persistente. A gravação é atômica a cada 60 segundos e também no STORE/encerramento normal do core. Uma interrupção abrupta pode perder o último intervalo ainda não gravado. O backup nativo inclui esse arquivo.

Um erro ao carregar o arquivo mantém o original intacto e bloqueia sua sobrescrita; o painel mostra um aviso. Corrija ou restaure o arquivo a partir de backup e reinicie o core. Remover um cadastro exclui sua linha dos totais atuais; recadastrar o mesmo CIDR recupera seus contadores mantidos no arquivo. A coleta não modifica a reputação nem invalida o cache de clientes a cada consulta.
