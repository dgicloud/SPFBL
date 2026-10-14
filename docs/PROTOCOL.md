# Protocolo e compatibilidade

SpamFox mantém o protocolo SPFBL. A nomenclatura SpamFox/SFOX aparece nos instaladores, logs e mensagens operacionais, enquanto o core, a licença e as atribuições SPFBL permanecem intactos.

## Portas

| Porta | Uso | Exposição recomendada |
|---|---|---|
| TCP 9877 | Consultas SPFBL de MTAs | Somente IPs autorizados |
| UDP 9877 | Comunicação P2P SPFBL, quando configurada | Conforme política de peers |
| UDP 53 | DNSBL | Pública somente se a zona estiver delegada |
| TCP 9875 | ADMIN SPFBL | Loopback/administrador; nunca pública |
| TCP 8080 | Backend HTTP SPFBL | Loopback; Nginx publica HTTPS |
| TCP 11333/11334 e 6379 | Rspamd e Redis | Loopback |

## Integração de envelope

Os instaladores de cPanel e Postfix consultam o core SPFBL usando o envelope SMTP. O modo `MONITOR` registra a decisão e mantém a entrega. A política de enforcement, quando desejada, deve ser habilitada conscientemente no cliente SPFBL depois de validar o comportamento do MTA.

## Integração de conteúdo

O gateway recebe uma cópia de mensagem já aceita em `POST /internal/sfox/scan`. A admissão é por IP/CIDR permitido; não há token de cPanel, identificador de servidor ou credencial no MTA. Rspamd pode aprender de forma conservadora e, para perfis habilitados, registrar feedback SPFBL por ticket.

Detalhes de implantação: [cPanel](../integrations/cpanel/README.md), [Postfix](../integrations/postfix/README.md) e [gateway](../integrations/content_scan/README.md).
