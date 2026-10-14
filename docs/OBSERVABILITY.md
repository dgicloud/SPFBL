# Observabilidade local

O bundle instala o comando `had-antispam status` e o serviço independente `had-antispam-observability.service`. O comando de status também consulta `PEER SHOW` no ADMIN loopback e imprime somente contagens agregadas: peers configurados, atividade recente/antiga/desconhecida, recepção `REPUTATION` e caps positivos. A atividade é o intervalo reportado pelo SPFBL, não uma conexão persistente; cap positivo não comprova uso em mensagem específica. Uma falha de consulta peer aparece como indisponibilidade do resumo e não derruba o status do core. O HTTP é vinculado somente a `127.0.0.1:9911`; não encaminhe essa porta pelo Nginx nem abra-a no firewall.

```bash
had-antispam status
curl --fail http://127.0.0.1:9911/health
curl --fail http://127.0.0.1:9911/metrics
systemctl status had-antispam-observability.service
```

`/health` responde JSON e HTTP 200 quando a unit do core está ativa e `VERSION` responde pelo ADMIN local. Se uma condição falhar, responde HTTP 503; o estado do timer `STORE` aparece no JSON para diagnóstico. `/metrics` usa o formato Prometheus text exposition e publica gauges para a unit do core, consulta ADMIN e timer. Também resume `PEER SHOW` em contagens sem hostname, IP ou e-mail: peers configurados, atividade recente/antiga/desconhecida, modo de recepção `REPUTATION` e caps de reputação positivos. `reputation_max_sum` é derivado da correlação por peer e não conta decisões que usaram reputação remota. A leitura de métricas tem cache de 30 segundos (falhas por 5 segundos) para limitar consultas ADMIN e ruído de log. Se o processo Java puder ser inspecionado em `/proc`, também publica memória residente, CPU acumulada e descritores abertos. As labels de versão/release são limitadas a uma série de build.

O serviço executa como `hadantispam`, sem permissões de escrita, e o instalador valida ambas as rotas em loopback antes de concluir. Os endpoints não têm autenticação porque o bind é estritamente local; não os publique em interfaces externas. Na última leitura SSH confirmada da VM, em 2026-10-03 03:11 UTC, a release nativa era `1.1.15-had-20261002-layout`, com core `SPFBL-3.0.0` e serviço vinculado a `127.0.0.1:9911`. Tentativas posteriores, incluindo consulta direta ao IP em 04:49 UTC, foram recusadas por autenticação SSH. O resumo P2P no CLI, os novos gauges e o cache estão no bundle local e ainda precisam ser implantados/verificados na VM.
