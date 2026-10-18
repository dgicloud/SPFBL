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

## Integração de envelope

Os instaladores de cPanel e Postfix consultam o core SPFBL usando o envelope SMTP. O modo `MONITOR` registra a decisão e mantém a entrega. A política de enforcement, quando desejada, deve ser habilitada conscientemente no cliente SPFBL depois de validar o comportamento do MTA.

## Treinamento de conteúdo

O Bayes nativo recebe mensagens `.eml` rotuladas pelo painel web. Os clientes de cPanel e Postfix consultam o envelope SPFBL e não transmitem mensagens completas. Consulte [Bayes nativo](CONTENT-BAYES.md), [cPanel](../integrations/cpanel/README.md) e [Postfix](../integrations/postfix/README.md).
