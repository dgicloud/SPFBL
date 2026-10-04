# Rspamd e Redis locais para SpamFox

Este instalador adiciona Rspamd e Redis na VM Ubuntu 24.04 que hospeda o core SPFBL. O scanner HTTP (11333), o controller (11334) e Redis (6379) ficam presos ao loopback. Ele não altera SPFBL, Exim, Postfix, nftables ou portas públicas.

O Bayes usa Redis com schema novo, no mínimo 200 mensagens aprendidas por classe e sem autolearning. Apenas HAM/SPAM revisados por operador devem ser treinados. Redis tem teto de 512 MiB, `noeviction` para preservar os exemplos aprendidos, AOF e limites systemd; Rspamd fica limitado a 1 GiB e dois workers. O scanner recebe mensagens de até 25 MiB e tem limite de processamento de 12 segundos.

Execute como root em Ubuntu 24.04:

```bash
bash install-local.sh
```

O instalador consulta o repositório APT oficial assinado do Rspamd, salva cópias de arquivos tocados em `/var/backups/had-antispam/rspamd/` e recusa substituir configurações locais existentes que não estejam marcadas como gerenciadas pela HAD.

## Estado funcional e integração

Rspamd/Redis locais foram instalados e validados na VM; o piloto ainda não foi ligado a cPanels/Postfix em produção. O cliente de conteúdo tem um desenho e uma implementação inicial separados do core: no Exim, um system filter `unseen pipe` entrega a cópia já enfileirada ao coletor; ele transmite em blocos HTTPS autenticados para uma fila limitada em RAM no gateway. O gateway responde `202` ao concluir o enfileiramento e dois workers classificam depois no Rspamd local. A conexão SMTP e a decisão de entrega não aguardam a classificação; a entrega local só pode esperar o tempo de upload da cópia.

O fluxo não cria outro `.eml` em disco no cPanel, Nginx ou gateway. O cliente aceita até 25 MiB, serializa um upload por cPanel; Nginx desativa request buffering e gravação do corpo; a fila central tem quatro posições além dos dois workers. Filas e mensagens em análise ficam apenas em RAM, então indisponibilidade, lotação ou reinício podem descartar eventos MONITOR sem afetar a mensagem original. Rspamd recebe `Flags: no_log`, usa seus dois workers locais e mantém o Bayes sem autotreinamento. Nenhum corpo/assunto é enviado ao Jev/OpenRouter.

Os módulos `integrations/content_scan/scan_gateway.py`, `scan_client.py` e o instalador Exim passaram testes locais de contrato e fila; a rota Nginx/gateway ainda precisa ser instalada na VM e o primeiro smoke Exim em cPanel precisa ser validado antes de distribuir aos demais. Ainda não existe integração after-queue equivalente de Postfix, painel de resultados, quarentena/rejeição ou fluxo de revisão e treinamento.

Para o aprendizado inicial, reunir exemplos legítimos e spam revisados por operador, balanceados; só então treinar com os endpoints privilegiados do controller, usando segredo local root-only. O mínimo configurado é 200 HAM e 200 SPAM antes de considerar o símbolo Bayes útil. Não use classificações automáticas do próprio filtro como rótulos.
