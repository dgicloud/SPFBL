# Documentação SpamFox

A documentação pública contém somente instruções reutilizáveis de instalação e operação. Registros de desenvolvimento, pilotos, auditorias e evidências não fazem parte deste repositório.

| Documento | Conteúdo |
|---|---|
| [Instalação](INSTALLATION.md) | Ordem de implantação e checagens mínimas |
| [Arquitetura](ARCHITECTURE.md) | Componentes e fronteiras de rede |
| [Protocolo](PROTOCOL.md) | Portas, compatibilidade e fluxo de dados |
| [Nginx e rotas](NGINX-ROUTES.md) | Vhosts, caminhos publicados e controles de acesso |
| [Backup e restore](BACKUP-RESTORE.md) | Proteção do core e do estado |
| [Observabilidade](OBSERVABILITY.md) | Saúde, métricas e logs |
| [Bayes nativo](CONTENT-BAYES.md) | Treino local por amostras EML e ativação conservadora |
| [Integrações](../integrations/README.md) | cPanel, Postfix e gateway com Bayes nativo |
