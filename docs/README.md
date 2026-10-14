# Documentação SpamFox

A documentação operacional está organizada por tema. O core continua sendo o SPFBL upstream; as integrações, instalação e operação SpamFox ficam nestes documentos.

| Documento | Conteúdo |
|---|---|
| [Integrações](../integrations/README.md) | Ordem de implantação e limites de cPanel, Postfix e gateway |
| [cPanel/Exim](../integrations/cpanel/README.md) | Cliente SPFBL, monitor e coletor after-queue |
| [Postfix](../integrations/postfix/README.md) | Cliente SPFBL e proteção contra o antigo `content_filter` |
| [Gateway/Rspamd](../integrations/content_scan/README.md) | Instalação central, rota HTTPS, allowlist e aprendizagem nativa |
| [Nginx e rotas](NGINX-ROUTES.md) | Vhosts, caminhos publicados e controles de acesso |
| [Instalação geral](INSTALLATION.md) | Base do core SPFBL nativo |
| [Arquitetura](ARCHITECTURE.md) | Componentes e fronteiras operacionais |

## Evidências

Os arquivos em [evidence/](evidence/) são registros históricos de validação e incidentes. Eles não são scripts de instalação nem representam o estado atual. Para instalar ou operar, use somente os READMEs de `integrations/`.
