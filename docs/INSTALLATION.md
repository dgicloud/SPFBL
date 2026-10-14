# Instalação e laboratório reproduzível

Baseline upstream: `7b0232e96f16faca151340b80c418838a800237f`. O ambiente Docker local é apenas desenvolvimento; o core ativo foi instalado nativamente em `/opt/spfbl`, seguindo a estrutura upstream, na release `1.1.15-had-20261002-layout`. O cPanel de homologação consulta diretamente a VM; uma mensagem real anterior recebeu greylisting temporário. O adapter HAD próprio continua separado do hook Exim upstream. O firewall local do cPanel usa CSF/iptables; a VM SPFBL usa nftables. A comunicação P2P UDP com `matrix.spfbl.net:9877` está ativa; a reputação efetivamente aplicada ainda não está comprovada (`reputationMax=0`). O listener upstream DNSBL está ativo em UDP 53; a zona `rbl.exemplo.com` foi delegada publicamente via Bunny e validada em `8.8.8.8`, inclusive depois do upgrade. Veja o [laudo atualizado da implantação](NATIVE-DEPLOYMENT-REPORT.md) e a [rechecagem P2P](evidence/production-observation-20261002.md).

## Origem e build

O checkout conserva o histórico upstream e `licence.txt`. O repositório traz `dist/SPFBL.jar` e bibliotecas em `lib/`, mas não traz `build.xml`, `pom.xml` ou Gradle. `debian/rules` não recompila o Java. O manifest distribuído registra Ant/Java 8, porém isso não fornece um projeto Ant reproduzível.

`packaging/audit/build-upstream.sh` compila as 59 fontes com `javac -encoding UTF-8 -source 8 -target 8 -cp lib/*`, copia os recursos Huffman `.obj` e grava um JAR separado em `.audit/runtime/SPFBL.jar`. A compilação inclui o ajuste HAD da coluna Entrega em `ServerHTTP.java`; o JAR distribuído nunca é sobrescrito. O JAR gerado deve ser iniciado com classpath explícito; seu manifest não embute `Class-Path`.

Imagem verificada: `eclipse-temurin:8-jdk@sha256:6f9f640cdc1a35e64b77daf1f48fcf7527953d9aa804916c8557e1aae954ecd5`, Java `1.8.0_504`. SHA-256 deste build com o ajuste visual: `c4fb4f72ca7f77c2b688395909aba65207c7bb7d140c9e289f1ccf901b966b16`. Não prometer hash idêntico de rebuild: timestamps do JAR não foram normalizados.

## Reprodução no Windows / PowerShell

Execute no diretório do checkout, com Docker Desktop ativo:

```powershell
New-Item -ItemType Directory -Path .audit -Force | Out-Null
docker run --rm --network none --mount "type=bind,src=$((Get-Location).Path),dst=/source,readonly" --mount "type=bind,src=$((Get-Location).Path)\.audit,dst=/audit" eclipse-temurin:8-jdk@sha256:6f9f640cdc1a35e64b77daf1f48fcf7527953d9aa804916c8557e1aae954ecd5 bash /source/packaging/audit/build-upstream.sh
Copy-Item packaging/audit/spfbl-lab.conf .audit/runtime/spfbl.conf
docker run --detach --name had-antispam-audit-core --network none --mount "type=bind,src=$((Get-Location).Path)\.audit,dst=/audit" --workdir /audit/runtime eclipse-temurin:8-jdk@sha256:6f9f640cdc1a35e64b77daf1f48fcf7527953d9aa804916c8557e1aae954ecd5 java -Xms128m -Xmx512m -cp 'SPFBL.jar:lib/*' net.spfbl.core.Core
```

As imagens precisam ser baixadas antes de executar com `--network none`. Não recriar um container homônimo já ativo: inspecione `docker ps` / `docker inspect` primeiro. Os volumes são descartáveis de laboratório; nunca apontar para dados de uma instalação real.

O smoke TCP usa um segundo container no namespace de rede do primeiro, sem publicar portas:

```powershell
docker run --rm --network container:had-antispam-audit-core --mount "type=bind,src=$((Get-Location).Path),dst=/source,readonly" python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f python /source/packaging/audit/protocol-smoke.py
```

O smoke cadastra um cliente loopback de laboratório. Não o usar contra produção. DNS externo não está disponível: o resultado `.boats` `GREYLIST` neste sandbox não representa a VM com listas/reputação públicas. Na homologação cPanel ativa, a mesma entrada retornou `BLOCKED` em modo MONITOR, sem corpo ou comparação com Imunify; veja [evidência do envelope](evidence/cpanel-boats-envelope-20261002.md).

Logs são gravados em `.audit/runtime/logs`; estado e chave em `.audit/runtime/data`. `.audit/` está excluído localmente pelo Git. Tratar a chave como segredo, sem publicá-la junto da evidência.

## Instalação nativa original: o que o código faz

`run/install.sh --install` instala pacotes, clona upstream, move binário/bibliotecas/dados para `/opt/spfbl`, cria links em `/etc/spfbl`, cron/logrotate e init script. Ele executa operações privilegiadas, reaproveita dados históricos e possui remoções amplas em install/uninstall. Não foi executado no host nem no servidor informado.

`run/spfbl.service` possui `WantedBy=multi-user.targe` e referencia init script; `debian/spfbl.service` tem working directory `/usr/share/spfbl`, usuário `spfbl` e múltiplos `ExecStop` em serviço simple. As units requerem validação/revisão antes de implantação. Não interpretar presença de arquivo como serviço operacional.

O bundle nativo mantém o processo sob `hadantispam` e restringe escrita ao estado/logs. ADMIN `9875` faz bind em wildcard, mas permanece bloqueado externamente. O backend HTTP `8080` também fica privado; na VM ativa, uma tabela NAT separada encaminha o tráfego externo dessa porta ao Nginx em `80`, que redireciona para HTTPS. A chamada externa não alcança diretamente o backend. O listener `9877` aceita `SPF`, `VERSION`, `ABUSE`, `HEADER`, `MALWARE`, `HOLDING` e `FIREWALL`; sua origem TCP é limitada pelo nftables da VM à allowlist `/etc/had-antispam/allowed-cpanels.txt`, que contém `198.51.100.160/32`, único IP de saída cPanel confirmado até agora. Para outros cPanels, cadastre cada IP/CIDR antes de abrir a consulta.

## Cadastro de cliente e P2P

O core usa CIDR/IP e permissões Client para consultas. Um comando de exemplo administrativo é `CLIENT ADD <IP-DO-CPANEL>/32 <hostname> SPFBL <postmaster>`, enviado somente por canal de gestão protegido. `VERSION` sozinho não prova cadastro/autorização; a consulta real e o registro Client precisam ser conferidos.

## Servidor DNSBL

O serviço nativo escuta consultas DNS em UDP/53. A zona pública funcional desta implantação é `rbl.exemplo.com`, delegada no DNS autoritativo com `rbl IN NS matrix.exemplo.com.`. A VM responde `127.0.0.2` para uma entrada listada e `NXDOMAIN` para uma não listada; a resposta TXT gera a URL de consulta do core. A zona `dnsbl.exemplo.net` está cadastrada no SPFBL, mas ainda precisa da delegação NS no DNS autoritativo de `exemplo.com` para se tornar pública.

A wiki mostra o atalho `spfbl dnsbl add`, mas o cliente shell upstream instalado (`/usr/local/bin/spfbl`, versão 2.17) não implementa o grupo `dnsbl`; ao receber esse argumento, imprime a ajuda. `spfbl` e `spfbl.sh` são utilitários diferentes: `spfbl version` testa a consulta SPFBL em TCP/9877, enquanto a wiki orienta importar cada linha do ZIP com `spfbl.sh superblock add "<linha>"`. A cópia `client/spfbl.sh` deste checkout ainda aponta para o endpoint ADMIN upstream por padrão, então não deve ser usada sem ajustar o destino. Nesta implantação, o ZIP já foi importado pelo ADMIN local da VM. Se aparecer `spfbl: command not found`, o comando foi executado em host/PATH sem o cliente; isso não é erro de importação. Não reimporte o ZIP para corrigir essa mensagem. Para administrar zonas, entre por SSH na VM central e use o protocolo ADMIN local:

```bash
printf 'DNSBL SHOW\n' | nc -w 3 127.0.0.1 9875
printf 'DNSBL ADD rbl.exemplo.com https://matrix.exemplo.com\n' | nc -w 3 127.0.0.1 9875
```

A zona `rbl.exemplo.com` já está cadastrada; o segundo comando é apenas o exemplo upstream de inclusão, não precisa ser repetido. Mantenha ADMIN `9875` bloqueado externamente: esse comando funciona via loopback e não requer publicar a porta. No DNS autoritativo, delegue o subdomínio à VM e libere UDP/53 na firewall da VM e no firewall/security group do provedor. A firewall CSF/iptables do cPanel é independente da firewall nftables da VM.

O comando `/usr/local/bin/spfbl version` deve ser executado no host onde o cliente shell foi instalado; na VM central ele responde `SPFBL-3.0.0`. O ZIP desta instalação (SHA-256 `0b2638ad6dbbbbde5f9130f2bbee1c3b8f4d7413a74ad46cae3173b19580801d`) já foi processado: 1.103.066 linhas, 1.083.738 inclusões novas, 19.323 existentes e cinco rejeitadas pelo core upstream; o relatório registra as rejeições. O cliente shell upstream também não implementa `spfbl dnsbl`; para consultar zonas, use `DNSBL SHOW` pelo ADMIN local acima. A porta ADMIN 9875 deve continuar sem publicação externa.

P2P exige hostname/IP compatíveis, UDP 9877 de entrada e saída, cadastro e políticas explícitas. O peer `matrix.spfbl.net:9877` está cadastrado com políticas REPUTATION/REPUTATION. Capturas confirmaram datagramas e comandos `REPUTATION` nos dois sentidos. Após `STORE` em 2026-10-03 01:41 UTC, `PEER SHOW` continuou com `reputationMax=0`. A análise agregada do snapshot encontrou no máximo 31 chaves com amostra local suficiente também presentes no mapa serializado do peer; o algoritmo requer mais de 32 tokens elegíveis dos dois lados e correlação positiva. Isso explica o cap zero no snapshot, embora os contadores remotos por token não tenham sido decodificados. Comunicação P2P está ativa, mas a reputação ainda não pesa no cálculo atual; admissão formal pelo operador também não foi confirmada. Veja [SPFBL-P2P-AUDIT.md](SPFBL-P2P-AUDIT.md), a [rechecagem P2P](evidence/production-observation-20261002.md) e o [laudo da implantação](NATIVE-DEPLOYMENT-REPORT.md).

## cPanel e backup

O instalador cPanel baseado no cliente oficial SPFBL foi executado no cPanel de homologação a pedido do usuário, trocando o endpoint SPFBL para `203.0.113.10`. Ele instalou ACLs que fazem enforcement; uma mensagem real anterior foi adiada com `4.7.1` após o core retornar `GREYLIST`. Esse caminho demonstra compatibilidade do protocolo, não implementa fail-open nem rollback HAD. A integração própria usa o adapter `MONITOR`/fail-open; o serviço e o hook persistente do Exim estão ativos em modo MONITOR, sem rejeitar nem adiar pelo HAD. Uma varredura sanitizada encontrou um evento `CONTINUE|decision|LAN`, mas não estabeleceu vínculo com uma transação SMTP enfileirada. Ainda faltam mensagem de teste correlacionada, entrega/retry e classificação Imunify. O cPanel instala o adapter por `integrations/cpanel/install-client.sh`; para instalar ou retirar o hook, use o gerenciador transacional `integrations/cpanel/manage_exim_acl.py`. Ele atua sobre a configuração Exim e não administra firewall. Consulte [SPFBL-CPANEL.md](SPFBL-CPANEL.md) e o [laudo operacional](NATIVE-DEPLOYMENT-REPORT.md).

O bundle instalado inclui `had-antispam-backup` e `had-antispam-restore`. O backup para o core de forma ordenada, preserva `data/`, `history/`, configuração e chave de tickets e reinicia o que estava ativo. O restore exige a mesma release e `--yes`, cria snapshot `pre-restore` e volta aos arquivos anteriores se o core não iniciar. Consulte [BACKUP-RESTORE.md](BACKUP-RESTORE.md) para comandos e limites. O primeiro backup operacional foi criado e validado na VM; falta copiá-lo para destino separado e fazer ensaio de restore fora do servidor de produção.

O bundle também disponibiliza `had-antispam status`, que mostra estado da unit, versão SPFBL por ADMIN loopback, release ativa e timer diário de `STORE`. `/health` e `/metrics` ficam num serviço separado em `127.0.0.1:9911`, sem acesso público. Na release ativa 1.1.9, `status` mostrou o core ativo e `/health` retornou `status=ok`; consulte [OBSERVABILITY.md](OBSERVABILITY.md) para indicadores e limites.
