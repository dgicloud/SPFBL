# Piloto local Rspamd/Redis — 2026-10-04

## Estado aplicado na VM

- VM Ubuntu 24.04; Rspamd 4.2.1 do repositório APT oficial assinado; Redis 7.0.15 dos pacotes Ubuntu.
- `had-antispam-core`, `rspamd` e `redis-server` ficaram ativos. O core SPFBL não foi reiniciado nem reconfigurado.
- Scanner Rspamd em `127.0.0.1:11333`, controller em `127.0.0.1:11334`, proxy em `127.0.0.1:11332` e Redis em `127.0.0.1:6379`/`::1:6379`. Nenhuma porta foi aberta na firewall da VM.
- Rspamd: dois workers, limite de mensagem 25 MB, processamento até 12 s e systemd `MemoryMax=1G`.
- Redis: `maxmemory=512 MiB`, `noeviction`, AOF com `appendfsync everysec` e systemd `MemoryMax=768 MiB`.
- Bayes usa Redis, OSB, schema novo, 11 tokens mínimos e 200 amostras mínimas por classe. `autolearn` retorna sempre `nil`; rótulos automáticos do classificador não treinam o modelo. A senha do controller é aleatória, guardada em arquivo root-only `0600`, e sua configuração tem apenas hash.
- Os logs de classificação usam formato reduzido sem IP, remetente, destinatário, assunto ou corpo.

## Verificação feita

`rspamadm configtest` retornou `syntax OK`. Redis respondeu `PONG`; `/ping` do worker normal respondeu; uma mensagem sintética local foi analisada por `rspamc` em aproximadamente 244 ms com resposta `no action` e score 2.50. A configuração efetiva confirmou Bayes em Redis, `min_learns=200` e autolearning desativado. A consulta sintética não foi aprendida como HAM ou SPAM.

## Limites do piloto

Nenhum MTA consulta ainda o scanner central; nenhuma mensagem real foi classificada nem rotulada. As regras Rspamd sozinhas já geram score, porém a qualidade de Bayes ainda depende de conjunto revisado de ao menos 200 HAM e 200 SPAM. Integração pós-aceite assíncrona para Exim e Postfix e transporte autenticado entre os servidores continuam pendentes. O conteúdo não deve ser gravado em outro `.eml`; o futuro worker deve transmitir a partir da fila normal do MTA, sem atrasar o `250` e sem enviar assunto/corpo à IA externa.
