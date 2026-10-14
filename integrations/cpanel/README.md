# SpamFox no cPanel/Exim

Esta integração mantém o core SPFBL intacto. O cliente consulta `203.0.113.10:9877`, aplica as ACLs compatíveis com cPanel e preserva os retornos do SPFBL. A marca SpamFox/SFOX aparece somente nas mensagens operacionais e ACLs do cliente.

## 1. Cliente SPFBL

Antes de instalar, cadastre o IP público do servidor no core e na allowlist da VM. Use uma caixa local real no teste:

```bash
curl -fsSLO https://raw.githubusercontent.com/dgicloud/SPFBL/hadcloud-cpanel-installer/client/spamfox.cpanel.sh
bash spamfox.cpanel.sh install
```

Para o adapter em MONITOR, que valida RCPT/DATA sem mudar a decisão do Exim:

```bash
curl -fsSLO https://raw.githubusercontent.com/dgicloud/SPFBL/hadcloud-cpanel-installer/client/spamfox-monitor.sh
bash spamfox-monitor.sh --test-recipient caixa@dominio.tld --check
bash spamfox-monitor.sh --test-recipient caixa@dominio.tld
```

`caixa@dominio.tld` precisa existir e ser roteada pelo Exim local. O instalador faz backup, valida `VERSION`, reconstrói Exim e aborta se a configuração não for segura.

## 2. Coletor Rspamd opcional

O coletor envia uma cópia de mensagem já aceita para `https://matrix.exemplo.com/internal/sfox/scan`. Ele não instala Rspamd nem Redis no cPanel.

```bash
curl -fsSLO https://raw.githubusercontent.com/dgicloud/SPFBL/hadcloud-cpanel-installer/client/spamfox-rspamd.cpanel.sh
bash spamfox-rspamd.cpanel.sh --test-recipient caixa@dominio.tld --check
bash spamfox-rspamd.cpanel.sh --test-recipient caixa@dominio.tld
```

A cópia Exim é MONITOR: falha de upload, timeout ou indisponibilidade do gateway não podem rejeitar ou reter o e-mail original. O Rspamd classifica a cópia na VM central; ações de Rspamd não controlam a entrega SMTP.

## Atualização e retorno

Use os scripts do mesmo pacote para atualizar. Para remover, use `rollback-client.sh` para o adapter SPFBL e o procedimento documentado do coletor. Não edite os arquivos gerenciados pelo cPanel manualmente; isso preserva o rollback transacional.