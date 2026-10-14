# Laudo de preparação do ambiente HAD AntiSpam

**Data do snapshot:** 1 de outubro de 2026 (horário de São Paulo)
**Finalidade:** preparar e validar um ambiente isolado para desenvolvimento do core original SPFBL.
**Escopo:** validação funcional inicial; este documento não é um pentest nem um laudo de prontidão para produção.

## Resultado

O ambiente de desenvolvimento está executando tanto no checkout local quanto na VM `antispam.exemplo.com`. O core foi compilado com Java 8 e respondeu aos testes sintéticos de protocolo. O código original em `src/`, `lib/`, `client/`, `run/`, `data/`, `dist/`, `debian/`, `web/` e `template/` permanece sem diferenças em relação ao upstream configurado.

A VM não recebeu ACL ou integração ativa no Exim. Para desenvolvimento, a homologação cPanel agora mantém somente um túnel SSH restrito e o adapter local em MONITOR, ambos como serviços systemd; o core continua sem portas públicas. O tráfego SPFBL fica numa rede Docker interna, sem saída para DNS ou peers públicos, e o P2P segue desligado.

## Ambiente instalado

- Destino: DNS `antispam.exemplo.com` → `203.0.113.10` (registro A confirmado em 2026-10-01). O sistema ainda informa o hostname interno `mg1-hcl-srv02`; esse hostname não foi alterado.
- Sistema observado: Ubuntu 24.04.3 LTS, arquitetura x86_64, 4 vCPU, 5,8 GiB de RAM e 61 GiB livres no disco raiz durante a inspeção.
- Docker Engine: `29.1.3`; Docker Compose: `2.40.3`, instalados dos pacotes do Ubuntu.
- Diretório de execução: `/opt/had-antispam-dev`.
- Imagem do core: Java 8 Temurin, compilada das fontes SPFBL no build da imagem; a saída do JAR fica separada do `dist/SPFBL.jar` original.
- Dados e logs persistentes do laboratório: `/opt/had-antispam-dev/.dev/data` e `/opt/had-antispam-dev/.dev/logs`.

O container do core roda como UID/GID `10001`, com filesystem raiz somente para leitura, todas as capabilities removidas, `no-new-privileges`, diretório temporário em `tmpfs` e sem mapeamentos de porta no host. A rede do core tem `internal=true`. Para o transporte, dois processos sem privilégios usam um socket Unix compartilhado: um sidecar na rede interna consulta `core:9877`; outro usa host networking, mas escuta exclusivamente em `127.0.0.1:19877`.

## Testes executados

| Teste | Resultado observado |
|---|---|
| Build das fontes upstream | Concluído com Java `1.8.0_504`; JAR produzido em caminho separado. |
| Saúde do container | `healthy` após a inicialização. |
| `VERSION` no listener ADMIN `9875` | `SPFBL-3.0.0`, aproximadamente 12,9 ms na execução remota registrada. |
| `VERSION` no listener SPFBL `9877` | `SPFBL-3.0.0`, aproximadamente 1,3 ms na execução remota registrada. |
| Consulta com IP malformado | Resposta `INVALID`. |
| Consulta com IP reservado `192.0.2.25` | Resposta `LAN`. |
| Persistência inicial | Arquivos de estado foram criados em `.dev/data`, pertencendo ao UID/GID `10001`. |
| Persistência após restart | PASS local e na VM: entrada sintética `198.51.100.91/32` adicionada, gravada, confirmada após reiniciar o core e removida com novo `STORE`. |
| Adapter HAD MONITOR | 18 testes passaram em Linux/Python 3.6.15 e no Python 3.6.8 do cPanel; o serviço Unix falha aberto e limpa o socket ao encerrar. |
| Instalador cPanel `validate` | PASS; `buildeximconf --acl_dry_run` aprovou e os hashes do hook, `/etc/exim.conf`, `.local` e `.localopts` permaneceram iguais. Não houve rebuild nem reload. |
| Guarda de rebuild cPanel (histórico, removida em 2026-10-02) | A versão temporária do manager parou por `nftables.service=failed`. A premissa estava errada para esse host: CSF/iptables é o firewall cPanel ativo. O manager atual não consulta nftables; install/uninstall real com rebuild, smoke e rollback passou, conforme [evidência atual](evidence/cpanel-had-monitor-install-rollback-20261002.md). |
| Adapter Postfix para core real | PASS com Python 3.6.8 no cPanel via túnel; envelope sintético RFC 5737 retornou `LAN` e policy `action=DUNNO` em 63 ms. Nenhuma configuração Postfix foi alterada. |
| Adapter Python 3.6.15 → core real | PASS no namespace Docker isolado; consulta sintética retornou `LAN`, `action=continue`, em 5 ms. |
| Túnel SSH restrito → core real | PASS em container descartável; adapter consultou o core pelo bridge loopback e socket Unix, retornando `LAN`/`continue` em 2 ms. A chave Ed25519 com `restrict` e `PermitOpen 127.0.0.1:19877` não alcançou ADMIN `9875`. |
| Bridges de transporte na VM | PASS; socket `core.sock` saudável, listener `127.0.0.1:19877`, UID/GID `10001:20001`, host network; o core continua sem portas publicadas. A consulta local pelo adapter retornou `LAN`/`continue` em 7 ms após restart. |
| Túnel real cPanel → VM → core | PASS; chave dedicada do usuário `had-tunnel` encaminhou consulta ao core real pelo endereço `antispam.exemplo.com`; adapter recebeu `LAN` em 73 ms. ADMIN `9875` foi negado pela mesma conta/chave. |
| Exim `readsocket` + fallback | PASS local e VM; Exim `4.98.2` usou o socket Unix `0660`, consultou o core em 6 ms localmente e 19 ms na VM, retornando `CONTINUE|decision|LAN`; socket ausente retornou `CONTINUE|socket_error`. |
| Serviços de desenvolvimento no cPanel | PASS; túnel e adapter systemd estão ativos e habilitados. Chave privada `root:root 0600`; socket do adapter `/run/had-antispam/monitor.sock`, `mailnull:mail 0660`. |
| Exim cPanel `readsocket` → core real | PASS em homologação, somente por `exim -be`; Exim `4.100.1` consultou pelo socket ativo e recebeu `CONTINUE|decision|LAN`. Com socket ausente, recebeu `CONTINUE|socket_error`. ACL ativa não foi alterada. |
| ACL RCPT MONITOR fake SMTP | PASS local e cPanel; sessões `-bh` usaram socket `0660` no grupo `mail` no host homologado, cobriram quatro recipients, null sender, RSET e reset de estado; socket ausente e timeout mantiveram RCPT aceito. Configuração temporária removida; nenhum hook ativo alterado. |
| Exposição de portas | `PortBindings={}`; nenhum listener do core publicado no host. |

O host cPanel foi inspecionado com Python `3.6.8` em `/usr/bin/python3`, sem runtime Python mais novo identificado. O adapter evita APIs posteriores; os 18 testes passaram com esse Python e também com Python `3.6.15` em Linux. Os serviços foram habilitados no cPanel de homologação sem hook Exim.

O hostname da VM resolve para `203.0.113.10`; não é necessário outro hostname para esse ambiente. Após instalar os bridges, o teste externo confirmou `22/tcp` disponível e `9875`, `9877` e `19877/tcp` inacessíveis. O túnel de saída, a conta/chave dedicada e o serviço adapter no cPanel consultam o core real. O hook Exim ativo ainda não foi instalado.

Os tempos são de poucas chamadas sintéticas e não representam teste de carga, percentis ou SLA.

## Ajustes feitos durante a preparação

1. **Permissões das pastas montadas:** na VM Linux, as pastas inicialmente pertenciam a `root`, e o processo sem privilégios não conseguia criar os arquivos de estado. As pastas de dados e logs foram atribuídas a `10001:10001`; a instância foi reiniciada e os arquivos passaram a ser criados. Os primeiros logs foram preservados em `.dev/logs-permission-diagnosis`.
2. **P2P desligado sem erro:** o core upstream tenta abrir o socket UDP P2P quando `hostname` é definido. O hostname fictício `localhost` provocou uma mensagem de erro de hostname não roteável. A configuração do laboratório agora deixa `hostname` sem definição; o log informa normalmente que o socket P2P não foi iniciado por falta de hostname. Isso mantém P2P fora do escopo desta instância isolada.
3. **Permissão da chave pública no servidor:** na primeira conexão, o sshd da VM recusou ler o arquivo `authorized_keys` por estar `0600` e pertencer ao root. O arquivo contém somente uma chave pública; ajustá-lo para `root:root 0644` permitiu a autenticação. A chave privada no cPanel permanece `root:root 0600`.

Esses pontos eram ajustes de configuração do laboratório, não vulnerabilidades confirmadas no SPFBL.

Na validação remota, o container estava parado com saída `143` (SIGTERM). O serviço foi iniciado novamente pelo Compose; então ficou `healthy`, passou o teste de persistência e permaneceu ativo. O primeiro comando de teste não alterou dados: abortou antes de conectar ao ADMIN por o container ainda estar parado.

### Reconciliação do estado em 2 de outubro de 2026

O snapshot acima documenta o estágio de 1 de outubro e não representa sozinho o estado atual. A VM agora também executa o core nativo `had-antispam-core.service`; os containers permanecem como laboratório isolado. No cPanel, o cliente upstream solicitado está ativo e suas ACLs Exim fazem enforcement; desde 2026-10-02 10:30 UTC, o adapter HAD também está conectado ao hook Exim em MONITOR, com dois rebuilds/reloads consecutivos validados. O firewall cPanel confirmado é CSF/iptables. O `nftables.service` falho é uma unidade separada e não demonstra falha do CSF. O gerenciador HAD deixou de usar esse serviço como pré-condição. Estado e evidências atuais estão em [NATIVE-DEPLOYMENT-REPORT.md](NATIVE-DEPLOYMENT-REPORT.md).

## Limites desta validação

Na data deste snapshot (1 de outubro), ainda não haviam sido testados: entrada/compartilhamento P2P, consultas DNS públicas e serviços externos, reputação distribuída, tickets/feedback reais, hook ativo, sessão SMTP real, Imunify/Rspamd, rollback do rebuild Exim ou carga de 100–1000 consultas/s. O smoke `-bh` então usou resposta sintética e configuração alternativa; a sessão real de homologação executada em 2 de outubro está no laudo operacional atualizado.

No cPanel de homologação, antes do ciclo de 2 de outubro, estavam instalados a chave dedicada, o túnel SSH restrito e o adapter MONITOR; o hook e o firewall não haviam sido alterados. O estado atual é diferente: o túnel foi desativado, o cPanel consulta diretamente a VM e o hook MONITOR passou por rebuild/reload e fake SMTP. Nenhum teste desta fase enviou e-mail real. Não trate a ativação MONITOR como autorização para enforcement.

## Operação do laboratório remoto

No servidor:

```bash
cd /opt/had-antispam-dev
docker compose -f compose.dev.yaml -f packaging/dev/compose.dev.vm.yaml --profile transport ps
docker compose -f compose.dev.yaml --profile test run --rm smoke
python3 packaging/dev/persistence-smoke.py
python3 -m unittest discover -s integrations/cpanel -p 'test_*.py' -v
docker compose -f compose.dev.yaml -f packaging/dev/compose.dev.vm.yaml --profile transport logs --tail 100 core core-unix-bridge core-loopback-bridge
ss -lntp 'sport = :19877'
```

No cPanel de homologação, consulte os serviços e o socket do adapter com:

```bash
systemctl status had-antispam-dev-tunnel.service had-antispam-dev-adapter.service
journalctl -u had-antispam-dev-tunnel.service -u had-antispam-dev-adapter.service --since today
stat -c '%U:%G %a %n' /etc/had-antispam-dev/ssh/id_ed25519 /run/had-antispam/monitor.sock
exim -bP acl_smtp_rcpt
```

Os arquivos instalados são `/etc/systemd/system/had-antispam-dev-tunnel.service`, `/etc/systemd/system/had-antispam-dev-adapter.service` e `/usr/local/libexec/had-antispam/had_antispam_client.py`. `acl_smtp_rcpt` permanece como o valor anterior, sem chamada HAD.

O checkout local continua sendo a fonte de desenvolvimento; a VM recebeu uma cópia dos arquivos necessários ao Compose, sem `.git`. Depois de alterar `src/` ou `lib/`, sincronize os arquivos atualizados para a VM e execute `docker compose -f compose.dev.yaml -f packaging/dev/compose.dev.vm.yaml --profile transport up --detach --build core core-unix-bridge core-loopback-bridge`. Preserve a propriedade `10001:10001` das pastas `.dev/data` e `.dev/logs` e `root:20001`/modo `0770` em `.dev/tunnel`.

## Próxima etapa técnica

O protótipo MONITOR consulta o core a partir da homologação cPanel; o snippet RCPT fake passou em Exim descartável e no cPanel `4.100.1`. O gerenciador passou por `validate`, duas instalações/rebuilds/reloads e uninstalls com restauração exata dos hashes do hook e Exim. Com o serviço local parado, Exim `-bh` produziu `CONTINUE|socket_error` e prosseguiu às ACLs seguintes. CSF/iptables permaneceu ativo; a unidade nftables separada não foi requisito. Próximos testes: observar SMTP real enquanto o hook está em MONITOR, entrega/Imunify e host Postfix de homologação.

**Higiene de acesso:** a senha administrativa da VM foi compartilhada na conversa. Rotacione-a e migre a automação para uma chave SSH dedicada antes do uso operacional contínuo; nenhuma senha foi gravada no repositório.
