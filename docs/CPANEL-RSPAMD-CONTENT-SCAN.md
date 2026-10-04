# Add-on leve Rspamd para cPanel/Exim

Este add-on contém somente o coletor Python, um hook Exim e o instalador, além da licença/atribuições do projeto. Ele não leva o core SPFBL/Java, Rspamd, Redis ou bibliotecas externas. O gateway deve estar previamente instalado na VM por `packaging/content-scan/install-gateway.sh`; sem esse gateway o preflight falha sem alterar Exim.

## Preparar token

Na VM central, depois de colocar o IP do cPanel na allowlist SPFBL:

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

## Instalar

Extraia o add-on e execute como root:

```bash
bash install-content-scan.sh --client-id HOST-CPANEL --token-file /root/had-content-scan.token --check
bash install-content-scan.sh --client-id HOST-CPANEL --token-file /root/had-content-scan.token
```

O script confirma TLS, endpoint, system filter e transporte pipe existente; reconstrói e testa o filtro Exim antes de reiniciar o serviço. Se `system_filter_pipe_transport` não estiver definido no WHM, a instalação para sem alteração e informa o pré-requisito.

## O que acontece

Depois do aceite SMTP, o Exim fornece uma cópia `unseen` da mensagem ao cliente por `stdin`. O coletor transmite blocos por HTTPS, sem arquivo `.eml` local. A VM limita a fila a quatro mensagens além de dois workers e responde `202` antes da classificação. O Exim nunca recebe a decisão do Rspamd; falha, limite de 25 MiB ou lotação preserva a entrega original e só produz um evento MONITOR. O resultado de Rspamd não altera SPFBL, reputação ou P2P.

A VM guarda corpos somente em RAM e pode perder mensagens da fila durante reinício. O Rspamd processa no ambiente HAD; assunto/corpo não são enviados ao Jev/OpenRouter. Para instalação, rollback e limites do piloto, consulte `README.md` do pacote.
