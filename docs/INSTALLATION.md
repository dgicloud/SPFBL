# Instalação

O SpamFox usa o core SPFBL nativo e adiciona clientes e ferramentas operacionais sem modificar o protocolo upstream.

## Ordem recomendada

1. Instale o core SPFBL na VM central usando o pacote nativo em [`../packaging/native/`](../packaging/native/README.md).
2. Defina o hostname público, TLS e a allowlist de IPs dos MTAs.
3. Cadastre cada MTA no core SPFBL e na allowlist da VM.
4. Instale o cliente adequado no MTA.
5. Opcionalmente, instale o gateway central para pontuação das cópias after-queue pelo Bayes nativo do core.

## Clientes

Os comandos atuais ficam nos guias de integração:

- [cPanel/Exim](../integrations/cpanel/README.md)
- [Postfix](../integrations/postfix/README.md)
- [Gateway de conteúdo e Bayes nativo](../integrations/content_scan/README.md)

O cliente SPFBL deve alcançar a porta TCP `9877` da VM central. Permita somente os IPs públicos dos MTAs conhecidos. ADMIN `9875` e o backend HTTP `8080` não devem ser expostos diretamente. O classificador Bayes e o gateway não dependem de Rspamd ou Redis.

## Checagem mínima

```bash
/usr/local/bin/spfbl version
nginx -t
systemctl is-active spfbl
```

No Postfix, execute também `postfix check`. No cPanel, faça rebuild do Exim pelo fluxo do instalador; não edite o arquivo gerado `/etc/exim.conf` manualmente.
