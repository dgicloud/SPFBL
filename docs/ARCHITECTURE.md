# Arquitetura

```mermaid
flowchart LR
  MTA[cPanel Exim ou Postfix] -->|SPFBL TCP 9877| Core[Core SPFBL nativo]
  MTA -. cópia after-queue opcional .-> Gateway[Gateway HTTPS restrito]
  Gateway --> Rspamd[Rspamd e Redis locais]
  Rspamd -. ticket SPAM de alta confiança .-> Core
  Core --> Panel[Painel HTTPS via Nginx]
```

## Componentes

| Componente | Responsabilidade | Exposição |
|---|---|---|
| Core SPFBL | Reputação, DNSBL, tickets e consultas SPFBL | TCP 9877 somente para MTAs autorizados; UDP 53 quando houver DNSBL |
| Nginx | TLS, painel e rota restrita de análise | HTTPS |
| Cliente cPanel/Postfix | Consulta envelope ao core | Saída TCP para a VM central |
| Gateway de conteúdo | Recebe cópias after-queue autorizadas | HTTPS restrito por IP |
| Rspamd/Redis | Análise de conteúdo, Bayes e histórico local | Somente loopback |

A decisão SMTP continua no MTA e no SPFBL. O gateway Rspamd analisa mensagens já aceitas, portanto não atrasa nem rejeita a mensagem original. Quando habilitado, o feedback envia ao SPFBL somente um ticket de spam elegível; nunca envia corpo ou assunto.

Consulte [Integrações](../integrations/README.md) para os limites e procedimentos de cada MTA.
