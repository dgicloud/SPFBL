# Integrações SpamFox

Esta pasta contém clientes para consultar o core SPFBL nos MTAs e ferramentas reutilizáveis de protocolo.

| Pasta | Função | Altera entrega? |
|---|---|---|
| `cpanel/` | Adapter SPFBL e ACLs persistentes para Exim/cPanel | Conforme a decisão SPFBL e a configuração do cliente |
| `postfix/` | Policy service SPFBL para Postfix | O pacote atual permanece em MONITOR e responde `DUNNO` |
| `common/` | Cliente de protocolo SPFBL e normalização de sinais técnicos | Não |

## Instalação

1. Instale o core SPFBL na VM central pelo pacote nativo.
2. Cadastre cada IP/CIDR público dos MTAs no core e na allowlist da VM.
3. Instale o cliente adequado no cPanel ou Postfix.
4. Treine o Bayes nativo pelo painel web com mensagens `.eml` rotuladas como SPAM ou HAM.

Os instaladores modulares desta pasta consultam o envelope no SPFBL. O Exim pode enviar cabeçalhos e metadados de entrega ao próprio core para exibição no painel; nenhuma mensagem `.eml` é enviada por essas integrações ao MTA ou classificador de terceiros. O instalador legado `client/spamfox.cpanel.sh` e o DirectAdmin são fluxos separados e podem habilitar SPAMD no core para mensagens elegíveis.

O core SPFBL e seu protocolo permanecem intactos. Identidade SpamFox/SFOX, direitos autorais e atribuições seguem a licença e os avisos do projeto em `licence.txt`.

Consulte [cPanel/Exim](cpanel/README.md), [Postfix](postfix/README.md) e [Nginx e rotas](../docs/NGINX-ROUTES.md).
