# Ambiente local de desenvolvimento

Este ambiente local compila o core original SPFBL com Java 8 dentro de Docker e executa uma instância descartável do HAD AntiSpam. O Compose local não instala nem modifica Exim/cPanel, não publica portas na rede local e não tenta entrar na rede pública P2P. A homologação cPanel é separada; desde 2026-10-02, o adapter direto e o hook Exim HAD em MONITOR estão ativos nela. A evidência operacional está em [cpanel-had-monitor-install-rollback-20261002.md](evidence/cpanel-had-monitor-install-rollback-20261002.md).

## Requisitos

- Docker Desktop com Docker Compose;
- Python 3 para o smoke test;
- checkout deste repositório.

Java no Windows não é necessário. A imagem de build usa `eclipse-temurin:8-jdk` fixada por digest. O build recompila as fontes originais para um JAR separado em `/opt/had-antispam/runtime`; não substitui `dist/SPFBL.jar`. O processo roda como usuário sem privilégios, com home temporário para o lock singleton; o estado e os logs ficam em `.dev/`.

## Iniciar e validar

No PowerShell, a partir da raiz do repositório:

```powershell
docker compose -f compose.dev.yaml up --build -d core
docker compose -f compose.dev.yaml ps
docker compose -f compose.dev.yaml --profile test run --rm smoke
python packaging/dev/persistence-smoke.py
python -m unittest discover -s integrations/cpanel -p 'test_*.py' -v
docker compose -f compose.dev.yaml logs --tail 100 core
```

O smoke envia `VERSION` aos listeners ADMIN e SPFBL e testa duas respostas determinísticas (`INVALID` para IP malformado e `LAN` para o bloco reservado de documentação). Ele roda num container Python temporário conectado à mesma rede interna; o core não publica portas no host. O teste de persistência adiciona somente `198.51.100.91/32` (faixa reservada para documentação), reinicia o core, confirma a entrada em `client.map` e a remove ao final. Execute-o apenas neste laboratório. Para acompanhar os logs, use `docker compose -f compose.dev.yaml logs -f core`. Para parar sem remover estado, use `docker compose -f compose.dev.yaml down`.

O protótipo `integrations/cpanel/had_antispam_client.py` implementa consulta de envelope em MONITOR, com conexão ao core de até 500 ms e consulta de até 800 ms. Testes unitários cobrem validação, parsing, fail-open e latência; o smoke de Exim descartável executa `readsocket` dentro do namespace do core. Consulte [o contrato e os limites](../integrations/cpanel/README.md).

O adapter também pode atender Exim por socket Unix local. O teste repetível instala Exim somente numa imagem Docker efêmera, chama `readsocket`, consulta o core e verifica o fallback quando o socket está ausente:

```powershell
docker build -f packaging/dev/Dockerfile.exim-readsocket -t had-antispam-exim-readsocket-test .
docker run --rm --network container:had-antispam-dev-core-1 had-antispam-exim-readsocket-test
docker compose -f compose.dev.yaml --profile test build tunnel-smoke
docker compose -f compose.dev.yaml --profile test run --rm tunnel-smoke
```

Esse ensaio passou com Exim `4.98.2`. A expansão, o fallback e a ACL RCPT de teste fake SMTP também passaram no Exim `4.100.1` do cPanel, usando configuração temporária isolada e socket `0660` no grupo `mail`. Na homologação, `exim -be` consultou o core real. Atualização de 2026-10-02: o hook MONITOR foi instalado pela API de rebuild do cPanel, duas reconstruções/reloads consecutivas passaram e a configuração ativa `-bh` consultou o core; mensagem SMTP real ainda não foi observada pelo hook.

O `tunnel-smoke` cria um OpenSSH descartável na rede Docker `internal=true`, gera chaves temporárias, aplica `AllowTcpForwarding local` e `PermitOpen 127.0.0.1:19877`, consulta o core por dois bridges e confirma que ADMIN `9875` é negado. O teste não publica SSH/SPFBL no host nem instala chaves persistentes.

Na VM Linux, o perfil `transport` liga um bridge de consulta ao core na rede Docker interna, grava um socket em `.dev/tunnel/core.sock` e executa um segundo bridge em host networking, vinculado exclusivamente a `127.0.0.1:19877`. O arquivo base continua sem `ports:`. Prepare a pasta com o GID numérico configurado (padrão `20001`) e inicie o core e bridges com o override de reinício:

```bash
install -d -o root -g 20001 -m 0770 .dev/tunnel
docker compose -f compose.dev.yaml -f packaging/dev/compose.dev.vm.yaml --profile transport up --build -d core core-unix-bridge core-loopback-bridge
ss -lntp 'sport = :19877'
```

O listener deve aparecer como `127.0.0.1:19877`. No cPanel, o túnel dedicado é `ssh -N -L 127.0.0.1:19877:127.0.0.1:19877 had-tunnel@antispam.hadcloud.srv.br`; o adapter consulta esse endpoint local. Os serviços persistentes instalados na homologação são `had-antispam-dev-tunnel.service` e `had-antispam-dev-adapter.service`. A porta `9877` do core e ADMIN `9875` permanecem sem publicação no host.

ADMIN não tem autenticação no upstream. O perfil padrão não publica portas e mantém os listeners acessíveis apenas aos containers ligados à rede Docker interna; não conecte essa rede a interfaces externas. A rede não tem saída para DNS, peers públicos ou serviços externos.

## Estado e rebuild

- `packaging/dev/spfbl.conf`: configuração de laboratório, montada somente para leitura;
- `.dev/data/`: dados gerados pela instância;
- `.dev/logs/`: logs gerados pela instância;
- `packaging/dev/persistence-smoke.py`: teste repetível de persistência após restart, com remoção da entrada sintética;
- `packaging/dev/Dockerfile`: recompila o core e as dependências originais;
- `packaging/audit/build-upstream.sh`: build Java 8 reutilizado sem alterar a árvore upstream.

Alterações em `src/` ou `lib/` entram após `docker compose -f compose.dev.yaml up --build -d core`. O estado local sobrevive a `down` e a rebuilds. `.dev/`, `.audit/` e classes compiladas estão no `.gitignore`.

## Limites deliberados

O hostname fica sem definição para impedir que o core original tente abrir o socket UDP P2P; HTTP/HTTPS, SMTP e DNSBL também não são iniciados pelo perfil local, e o container não tem rota externa. Assim, este ambiente serve para desenvolver e exercitar o protocolo/core com dados sintéticos. Resultados que dependam de DNS público, acesso SPFBL, P2P, entrega SMTP, Imunify ou Exim precisam de um laboratório separado, explicitamente configurado e autorizado.

Não execute `run/install.sh`, `client/spamfox.cpanel.sh` ou rebuild Exim como parte deste ambiente. O protótipo HAD já consulta em MONITOR; sua chamada pela ACL, fail-open SMTP, instalação e rollback continuam gates futuros.
