# Integrações SpamFox

Esta pasta contém as integrações entre o core SPFBL, os MTAs e o gateway de conteúdo com Bayes nativo.

| Pasta | Função | Altera entrega? |
|---|---|---|
| `cpanel/` | Adapter SPFBL para Exim/cPanel e coletor Exim opcional | Policy em MONITOR; coletor é cópia accepted after-queue |
| `postfix/` | Policy SPFBL para Postfix | Não. Responde sempre `DUNNO` em MONITOR |
| `content_scan/` | Cliente after-queue, gateway Bayes nativo e feedback opcional de ticket SPFBL | Não. Gateway pontua cópias aceitas |
| `common/` | Cliente de protocolo SPFBL e validação de sinais | Não |

## Ordem de implantação

1. Instale e valide o core SPFBL na VM central.
2. Cadastre o IP público de cada MTA como `client` no SPFBL e permita-o no firewall/allowlist da VM.
3. Instale o cliente SPFBL no cPanel ou Postfix.
4. Opcionalmente instale o gateway de conteúdo na VM central e o coletor **apenas onde houver uma cópia after-queue comprovadamente segura**.

O core SPFBL permanece nativo. SpamFox identifica os scripts, mensagens e operação; direitos e atribuições do SPFBL permanecem em `licence.txt` e nos arquivos upstream.

## Endereços da implantação HAD

- Core SPFBL: `203.0.113.10:9877`
- Painel e gateway HTTPS: `https://matrix.exemplo.com`
- Gateway de conteúdo: `POST /internal/sfox/scan` (restrito à allowlist)
- Gateway Bayes: loopback na VM central; pontuação e aprendizado supervisionado fazem parte do core SPFBL.

Veja os READMEs de cada pasta para comandos e limites operacionais.
Documentacao detalhada do proxy: [Nginx e rotas](../docs/NGINX-ROUTES.md).
