# Componentes Rspamd legados

O fluxo suportado do SpamFox usa o Bayes nativo do core SPFBL. O gateway after-queue consulta esse classificador em loopback; Rspamd e Redis não são dependências e não devem ser instalados para uma nova implantação.

Os arquivos deste diretório foram mantidos temporariamente como referência de migração e recuperação de instalações antigas. O instalador `install-spamfox-rspamd.sh` está desativado para evitar reativação acidental. Para instalar o gateway atual, siga [Integração do monitor e Bayes nativo](../../integrations/content_scan/README.md). Para treinar mensagens `.eml`, use a tela administrativa nativa documentada em [Bayes nativo](../../docs/CONTENT-BAYES.md).
