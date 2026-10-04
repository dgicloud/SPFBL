# Add-on leve Rspamd para cPanel/Exim

Este add-on contém somente o coletor Python, um hook Exim e o instalador, além da licença/atribuições do projeto. Ele não leva o core SPFBL/Java, Rspamd, Redis ou bibliotecas externas. O gateway deve estar previamente instalado na VM por `packaging/content-scan/install-gateway.sh`; sem esse gateway o preflight falha sem alterar Exim.

## Pré-requisitos e preflight

Antes de emitir um token, configure o transporte pelo WHM (não edite `/etc/exim.conf`): abra **Service Configuration → Exim Configuration Manager → Advanced Editor → Add additional configuration setting**, informe `system_filter_pipe_transport` como chave e `address_pipe` como valor, e salve. O `address_pipe` já é fornecido pelo cPanel como transporte pipe; o Exim exige um transporte explícito para comandos `pipe` no system filter. Depois, confirme:

```bash
/usr/sbin/exim -bP system_filter_pipe_transport system_filter_user system_filter_group
```

Extraia o add-on e rode o preflight como root; ele não precisa de token nem altera o Exim:

```bash
bash install-content-scan.sh --client-id HOST-CPANEL --check
```

O preflight confirma transporte, usuário/grupo do filtro, TLS e permissão da rota. Só depois de passar, na VM central, cadastre o IP do cPanel na allowlist SPFBL e crie uma credencial individual:

```bash
had-content-scan-clients add HOST-CPANEL --cidr IP_PUBLICO/32
```

Transfira o token apresentado uma única vez por canal seguro. No cPanel, grave-o sem colocá-lo no histórico:

```bash
read -r -s -p 'Token do gateway: ' HAD_SCAN_TOKEN
printf '\n'
umask 077
printf '%s' "$HAD_SCAN_TOKEN" > /root/had-content-scan.token
unset HAD_SCAN_TOKEN
```

Então instale como root:

```bash
bash install-content-scan.sh --client-id HOST-CPANEL --token-file /root/had-content-scan.token
```

O instalador detecta o usuário e grupo configurados para o system filter, guarda o token em `/etc/had-content-scan/client.json` (root e grupo do filtro) e cria o lock para o usuário do filtro. Antes do rebuild, testa leitura do token e acesso ao lock como essa mesma conta.

## O que acontece

Depois do aceite SMTP, o Exim fornece uma cópia `unseen` da mensagem ao cliente por `stdin`. O coletor transmite blocos por HTTPS, sem arquivo `.eml` local. A VM limita a fila a quatro mensagens além de dois workers e responde `202` antes da classificação. O Exim nunca recebe a decisão do Rspamd; falha, limite de 25 MiB ou lotação preserva a entrega original e só produz um evento MONITOR. O resultado de Rspamd não altera SPFBL, reputação ou P2P.

A VM guarda corpos somente em RAM e pode perder mensagens da fila durante reinício. O Rspamd processa no ambiente HAD; assunto/corpo não são enviados ao Jev/OpenRouter. Para instalação, rollback e limites do piloto, consulte `README.md` do pacote.
