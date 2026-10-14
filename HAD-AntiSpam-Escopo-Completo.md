# HAD AntiSpam — Escopo Completo, Fork do SPFBL, P2P, Reputação e Integração cPanel

## 1. Contexto do projeto

O **HAD AntiSpam** será criado a partir de um fork do projeto open source **SPFBL**.

Projeto upstream:

```text
https://github.com/leonamp/SPFBL
```

A intenção é usar o core existente do SPFBL como base, especialmente:

- reputação;
- SPF;
- HELO;
- IP reputation;
- domínio;
- blacklist;
- whitelist;
- greylist;
- spamtrap;
- DNSBL;
- tickets;
- feedback;
- P2P;
- mecanismos de classificação e decisão SMTP;
- clientes existentes para integração com MTAs.

O projeto será adaptado para uso interno da HAD Cloud, com possibilidade de inclusão de alguns parceiros/amigos, sem foco inicial em comercialização pública.

A prioridade técnica é aproveitar a inteligência existente do SPFBL, inclusive a rede P2P e serviços externos associados, sempre que isso for tecnicamente possível e permitido.

---

# 2. Objetivo principal

Criar uma solução centralizada de antispam para os servidores da HAD Cloud, inicialmente focada em:

```text
cPanel + Exim
```

O HAD AntiSpam deverá atuar antes da aceitação definitiva da mensagem.

Fluxo desejado:

```text
Internet
   |
   v
Exim / cPanel
   |
   v
HAD AntiSpam
   |
   +--> PASS ----------> continua processamento
   |
   +--> WHITE ---------> continua com confiança elevada
   |
   +--> FLAG ----------> aceitar e marcar como spam
   |
   +--> GREYLIST ------> 451
   |
   +--> BLOCKED -------> 550
   |
   +--> FAIL ----------> 550
   |
   +--> SPAMTRAP ------> descartar / registrar
   |
   +--> NXDOMAIN ------> 550
   |
   +--> INVALID -------> 550
```

Depois do HAD AntiSpam, mensagens aceitas continuam para:

```text
Imunify Email
   |
   v
Rspamd
   |
   +--> Inbox
   |
   +--> Junk
```

O HAD AntiSpam não deverá substituir inicialmente o Imunify Email.

---

# 3. Responsabilidade de cada camada

## HAD AntiSpam

Responsável principalmente por:

```text
reputação
SPF
HELO
PTR
IP
sender
domain
DNSBL
DNSWL
P2P
greylist
spamtrap
blocklist
allowlist
decisão SMTP antecipada
```

## Imunify Email / Rspamd

Responsável principalmente por:

```text
conteúdo
Bayes
URLs
phishing
MIME
anexos
classificação pós-aceite
Spam/Junk
```

---

# 4. Estratégia do projeto

O projeto NÃO deve começar reescrevendo o SPFBL.

A sequência correta é:

```text
1. clonar
2. entender
3. compilar
4. executar
5. testar
6. auditar
7. documentar
8. validar P2P
9. validar integração cPanel
10. somente depois alterar
```

Não remover inicialmente:

```text
matrix.spfbl.net
score.spfbl.net
dnsbl.spfbl.net
dnswl.spfbl.net
P2P
tickets
reputation
```

antes de saber exatamente o impacto.

---

# 5. Fork

Clonar:

```bash
git clone https://github.com/leonamp/SPFBL.git had-antispam
cd had-antispam
```

Configurar upstream:

```bash
git remote rename origin upstream
```

Depois adicionar repositório HAD:

```bash
git remote add origin git@github.com:HADCloud/had-antispam.git
```

Estrutura:

```text
upstream = SPFBL original
origin   = HAD AntiSpam
```

---

# 6. Licença

O SPFBL é GPL-3.0.

O fork deve:

- manter avisos de copyright;
- manter arquivos de licença;
- respeitar obrigações da GPL;
- não remover atribuições obrigatórias;
- documentar claramente quais componentes derivam do SPFBL.

O rebranding não deve apagar informações legais obrigatórias.

---

# 7. Objetivo imediato do Codex

A primeira tarefa NÃO é fazer rebranding.

A primeira tarefa é realizar uma auditoria técnica completa do SPFBL.

O Codex deve responder:

```text
Como funciona?
Como instala?
Como persiste reputação?
Como funciona P2P?
Como entra na rede?
Precisa autorização?
Como conversa com Exim?
Como funciona fail-open?
Quais serviços externos são usados?
```

---

# 8. Arquivos de documentação obrigatórios

O Codex deverá gerar:

```text
docs/ARCHITECTURE.md
docs/INSTALLATION.md
docs/PROTOCOL.md
docs/SPFBL-P2P-AUDIT.md
docs/SPFBL-EXTERNAL-SERVICES.md
docs/SPFBL-REPUTATION.md
docs/SPFBL-CPANEL.md
docs/HAD-ANTISPAM-ARCHITECTURE.md
docs/UPSTREAM-DIFF.md
```

---

# 9. Auditoria do código P2P

Pesquisar:

```text
P2P
Peer
PeerNode
PeerList
Reputation
Distribution
Broadcast
Matrix
score.spfbl.net
matrix.spfbl.net
dnsbl.spfbl.net
dnswl.spfbl.net
spfbl.net
```

Executar buscas como:

```bash
grep -Rni "P2P" .
grep -Rni "Peer" .
grep -Rni "matrix.spfbl.net" .
grep -Rni "score.spfbl.net" .
grep -Rni "dnsbl.spfbl.net" .
grep -Rni "dnswl.spfbl.net" .
grep -Rni "spfbl.net" src
```

Documentar todos os arquivos relevantes.

---

# 10. Descoberta de peers

Descobrir exatamente como um servidor encontra outros peers.

Possibilidades:

```text
bootstrap server
DNS
lista estática
matrix.spfbl.net
configuração manual
peer discovery
broadcast
seed list
```

Não assumir.

Confirmar pelo código.

---

# 11. Autenticação P2P

Descobrir se peers precisam de:

```text
token
API key
certificado
IP autorizado
hostname autorizado
assinatura
challenge
trust explícito
```

ou se qualquer servidor pode participar.

---

# 12. Portas P2P

Documentar:

```text
porta TCP
porta UDP
bind address
protocolo
timeout
retry
```

---

# 13. Dados compartilhados entre peers

Confirmar exatamente o que é compartilhado.

Pode incluir:

```text
IP reputation
domain reputation
sender reputation
HELO reputation
spam count
ham count
probabilidade de spam
tickets
blocklist
whitelist
complaints
spamtrap events
```

Não presumir.

---

# 14. Reputação

Documentar:

```text
quais entidades possuem reputação
como o score é armazenado
como é persistido
como spam aumenta score negativo
como HAM reduz
se existe decay
se existe peso temporal
se existe reputação por ASN
se existe reputação por domínio
se existe reputação por remetente
se existe reputação por HELO
como IPv6 é tratado
```

Identificar principais classes.

---

# 15. HAM e SPAM

Descobrir como o SPFBL calcula:

```text
HAM
SPAM
```

Verificar se há fórmula equivalente a:

```text
P = SPAM / (HAM + SPAM)
```

Confirmar no código.

Não depender apenas de documentação externa.

---

# 16. Reputação local vs reputação P2P

Descobrir se o SPFBL diferencia:

```text
local reputation
peer reputation
global reputation
external reputation
```

Se houver separação, documentar:

```text
classes
campos
funções
arquivos
persistência
```

Objetivo futuro:

```text
HAD_LOCAL
SPFBL_P2P
EXTERNAL_DNSBL
```

---

# 17. Trust entre peers

Descobrir se peers possuem níveis de confiança.

Pesquisar por conceitos como:

```text
trust
trusted peer
peer score
peer reputation
trusted node
whitelist peer
```

Responder:

```text
todo peer tem o mesmo peso?
um peer malicioso pode injetar reputação falsa?
```

---

# 18. Proteções contra abuso P2P

Investigar proteção contra:

```text
Sybil attack
peer falso
spam de reputação
feedback fraudulento
spamtrap falso
replay
spoofing
poisoning
```

Se não houver proteção, registrar como risco.

---

# 19. Matrix SPFBL

Pesquisar todo uso de:

```text
matrix.spfbl.net
```

Documentar:

```text
função
protocolo
autenticação
dependência
fallback
limites
bootstrap
reputação
consulta
```

Responder:

```text
matrix.spfbl.net é obrigatória?
é somente interface web?
é bootstrap?
é fonte de reputação?
precisa autorização?
```

---

# 20. Score SPFBL

Pesquisar:

```text
score.spfbl.net
```

Documentar:

```text
quando é consultado
como é consultado
qual protocolo
qual resposta
se exige autorização
se possui cache
se possui fallback
```

---

# 21. DNSBL SPFBL

Pesquisar:

```text
dnsbl.spfbl.net
```

Documentar:

```text
como consulta
TTL
cache
retornos
scores
timeout
NXDOMAIN
SERVFAIL
```

---

# 22. DNSWL SPFBL

Pesquisar:

```text
dnswl.spfbl.net
```

Documentar:

```text
como consulta
quando aumenta confiança
como influencia score
como trata timeout
```

---

# 23. Todos os serviços externos

Gerar tabela:

| Host | Arquivo | Função | Obrigatório | Precisa autorização | Pode substituir |
|---|---|---|---|---|---|

Incluir todo host:

```text
*.spfbl.net
```

---

# 24. Pergunta crítica

Responder de forma conclusiva:

```text
Se eu subir had-antispam01.hadcloud.com.br com o código original SPFBL,
ele entra automaticamente na rede P2P existente?
```

Resposta final deve ser uma destas:

```text
SIM
NÃO
PARCIAL
NÃO CONFIRMADO
```

Justificar com evidência de código.

---

# 25. Se precisa autorização

Identificar:

```text
quem autoriza
onde solicita
qual parâmetro
qual configuração
qual identificador
qual IP
qual hostname
qual token
```

---

# 26. Rede P2P privada HAD

Investigar se podemos operar:

```text
HAD Peer 1
HAD Peer 2
HAD Peer 3
```

independentemente da rede pública.

Arquitetura:

```text
             HAD P2P
                |
       +--------+--------+
       |        |        |
    Node01   Node02   Node03
       |        |        |
    Valinor   Moria    Anakin
```

Todos compartilhando reputação.

Documentar configuração necessária.

---

# 27. Arquitetura híbrida

Investigar possibilidade de:

```text
HAD P2P privado
       +
SPFBL P2P público
```

Arquitetura desejada:

```text
                    SPFBL PUBLIC
                         |
                         v
                      Node HAD
                         |
              +----------+----------+
              |                     |
          HAD Peer 2             HAD Peer 3
```

Responder se é possível e como.

---

# 28. Prioridade de reputação

Se o sistema permitir múltiplas fontes, documentar como combinar:

```text
reputação local
reputação P2P
DNSBL
DNSWL
SPF
HELO
PTR
```

Não alterar algoritmo ainda.

Apenas documentar comportamento atual.

---

# 29. Integração cPanel atual

Auditar:

```text
client/spfbl.pl
```

e todos os componentes relacionados a Exim/cPanel.

Responder:

```text
onde instala
qual ACL utiliza
quais variáveis Exim lê
qual protocolo usa
como consulta servidor
como interpreta resposta
como lida com timeout
como lida com indisponibilidade
```

---

# 30. Estágios SMTP

Documentar em qual estágio o SPFBL atua:

```text
CONNECT
EHLO
MAIL FROM
RCPT TO
DATA
```

Prioridade futura HAD:

```text
RCPT TO
```

porque nesse estágio já temos:

```text
IP
HELO
MAIL FROM
RCPT TO
```

---

# 31. Mapeamento de respostas

Localizar todas as respostas possíveis.

Exemplo esperado:

```text
PASS
WHITE
FLAG
GREYLIST
LISTED
BLOCKED
SPAMTRAP
NXDOMAIN
INVALID
FAIL
SOFTFAIL
NEUTRAL
NONE
HOLD
```

Criar tabela:

| Resposta | Significado | Ação atual | Ação HAD |
|---|---|---|---|

---

# 32. Ações HAD propostas

## PASS

```text
continuar processamento
```

## WHITE

```text
continuar com confiança alta
```

## FLAG

```text
aceitar e marcar como spam
```

Headers:

```text
X-Spam-Flag: YES
X-HAD-AntiSpam-Result: FLAG
```

## GREYLIST

```text
451 4.7.1 Temporary rejection by HAD AntiSpam
```

## BLOCKED

```text
550 5.7.1 Message rejected by HAD AntiSpam
```

## FAIL

```text
550 5.7.1 SPF validation failed
```

## NXDOMAIN

```text
550 5.1.8 Sender domain does not exist
```

## INVALID

```text
550 5.7.1 Invalid sender
```

## SPAMTRAP

Comportamento configurável:

```text
accept-drop
reject
accept-report
```

Default sugerido:

```text
accept-drop
```

---

# 33. Fail-open

Obrigatório.

Se HAD AntiSpam estiver indisponível:

```text
timeout
connection refused
DNS failure
service unavailable
internal error
```

o Exim deve continuar.

Fluxo:

```text
HAD AntiSpam OFFLINE
        |
        v
Exim continua
        |
        v
Imunify Email / Rspamd
```

Nunca interromper recebimento por falha do HAD.

---

# 34. Timeout

Meta:

```text
connect timeout <= 500 ms
total timeout <= 1 s
```

Ideal:

```text
P95 < 200 ms
```

Ao exceder:

```text
FAIL OPEN
```

---

# 35. Modo monitor-only

Obrigatório antes de produção.

Modo:

```text
MONITOR
```

Comportamento:

```text
HAD consulta
HAD decide
HAD registra
Exim NÃO bloqueia
```

Adicionar header opcional:

```text
X-HAD-AntiSpam-Monitor: BLOCKED
```

Objetivo:

```text
medir falso positivo
comparar com Imunify
comparar com SpamAssassin
validar reputação
```

---

# 36. Caso real de teste

Utilizar como cenário:

```text
IP:
57.129.161.225

HELO:
setor70f.ventaro.boats

MAIL FROM:
secretaria42@setor70f.ventaro.boats
```

Comparar:

```text
resultado SPFBL
score SpamAssassin
score Imunify/Rspamd
ação HAD
```

Não criar regra fixa para `.boats` apenas para fazer o teste passar.

---

# 37. Integração cPanel

Criar:

```text
integrations/
└── cpanel/
    ├── install.sh
    ├── uninstall.sh
    ├── update.sh
    ├── healthcheck.sh
    ├── had-antispam-client
    ├── exim/
    │   ├── acl-connect.conf
    │   ├── acl-mail.conf
    │   ├── acl-rcpt.conf
    │   └── acl-data.conf
    └── README.md
```

---

# 38. Não editar exim.conf diretamente

Não modificar:

```text
/etc/exim.conf
```

diretamente.

Usar mecanismos persistentes do cPanel.

A integração deve sobreviver a:

```bash
/scripts/buildeximconf
```

---

# 39. Instalador cPanel

O instalador deverá:

```text
1. detectar cPanel
2. detectar Exim
3. detectar Imunify
4. detectar SpamAssassin
5. criar backup
6. instalar ACL
7. validar configuração
8. rebuild Exim
9. testar
10. reload/restart apenas se necessário
11. rollback automático em erro
```

---

# 40. Rollback

Obrigatório.

Comando esperado:

```bash
had-antispam-cpanel uninstall
```

ou:

```bash
./uninstall.sh
```

Resultado:

```text
Exim volta exatamente ao estado anterior.
```

---

# 41. Configuração cliente

Arquivo:

```text
/etc/had-antispam/client.conf
```

Exemplo:

```ini
SERVER=antispam.hadcloud.com.br
PORT=9877
TIMEOUT=1
FAIL_OPEN=true
MONITOR_MODE=true
SERVER_ID=valinor
```

---

# 42. Autorização de clientes

Inicialmente reutilizar mecanismo original SPFBL se possível.

Documentar:

```text
clients
CIDR
IP
hostname
token
```

Posteriormente avaliar:

```text
API key
mTLS
server token
```

---

# 43. Multi-servidor

Objetivo:

```text
VALINOR recebe spam
        |
        v
HAD AntiSpam
        |
reputação atualizada
        |
        +---------> MORIA
        |
        +---------> ANAKIN
        |
        +---------> demais servidores
```

A reputação deve ser compartilhada entre os servidores HAD.

---

# 44. Headers HAD

Após validação de compatibilidade, considerar:

```text
Received-HAD-AntiSpam
X-HAD-AntiSpam
X-HAD-AntiSpam-Result
X-HAD-AntiSpam-ID
```

Não alterar formato de ticket antes da auditoria.

---

# 45. Tickets

Preservar sistema de tickets.

Objetivo:

```text
mensagem aceita
      |
      v
ticket
      |
      v
feedback
      |
      v
reputação
```

---

# 46. Feedback

Futuro:

```text
Report Spam
Not Spam
```

Inicialmente utilizar mecanismo original SPFBL.

---

# 47. Spamtrap

Preservar.

Documentar:

```text
como cria
como persiste
como identifica
como penaliza reputação
como compartilha via P2P
```

---

# 48. DNSBL HAD

Preservar servidor DNSBL existente no core se possível.

Futuro:

```text
dnsbl.antispam.hadcloud.com.br
```

Antes disso, validar completamente funcionamento original.

---

# 49. Logs

Registrar:

```text
timestamp
server
source IP
HELO
MAIL FROM
RCPT TO
resultado SPF
resultado HAD
ticket
ação
latência
```

Não armazenar corpo completo no MVP.

---

# 50. Privacidade

Não armazenar:

```text
senha
SMTP AUTH credentials
corpo completo
anexos
segredos
```

---

# 51. Compatibilidade Imunify

Não remover nem desabilitar:

```text
Imunify Email
Rspamd
SpamAssassin
```

Fluxo:

```text
SMTP
 |
 v
Exim ACL
 |
 v
HAD AntiSpam
 |
 +-- BLOCK -> 550
 |
 +-- GREYLIST -> 451
 |
 +-- PASS
      |
      v
Imunify Email / Rspamd
```

---

# 52. Rebranding

Somente depois da auditoria.

Substituir visualmente:

```text
SPFBL -> HAD AntiSpam
```

onde for seguro.

Não remover:

```text
licença
copyright
avisos GPL
```

---

# 53. Domínios HAD futuros

Propostos:

```text
antispam.hadcloud.com.br
dnsbl.antispam.hadcloud.com.br
panel.antispam.hadcloud.com.br
```

Não substituir `*.spfbl.net` antes de saber exatamente o papel de cada dependência.

---

# 54. Dashboard

Segunda fase.

Páginas:

```text
Dashboard
Events
Reputation
Blacklist
Whitelist
Spamtraps
Servers
DNSBL
Settings
```

---

# 55. Dashboard principal

Exibir:

```text
consultas 24h
PASS
BLOCKED
GREYLIST
FLAG
FAIL
SPAMTRAP

top IPs
top senders
top domains
top HELOs

latência média
servidores conectados
```

---

# 56. API

Segunda fase.

Não substituir protocolo SPFBL inicialmente.

Criar adapter REST futuramente:

```text
POST /api/v1/check
GET /api/v1/events
GET /api/v1/reputation/{type}/{value}
POST /api/v1/blocklist
POST /api/v1/allowlist
POST /api/v1/report/spam
POST /api/v1/report/ham
```

---

# 57. Estrutura de repositórios futura

Preferência:

```text
had-antispam-core
had-antispam-cpanel
had-antispam-control-plane
had-antispam-dashboard
```

Ou inicialmente:

```text
had-antispam/
├── src/
├── client/
├── web/
├── integrations/
│   └── cpanel/
├── docs/
└── packaging/
```

---

# 58. Branches

Sugestão:

```text
main
develop
upstream-sync
feature/cpanel-integration
feature/rebranding
feature/monitor-mode
feature/dashboard
```

---

# 59. Atualizações upstream

Manter possibilidade de:

```bash
git fetch upstream
git checkout master
git merge upstream/master
```

ou processo equivalente.

Documentar conflitos.

---

# 60. Serviço systemd

Nome futuro:

```text
had-antispam.service
```

Comandos:

```bash
systemctl start had-antispam
systemctl stop had-antispam
systemctl restart had-antispam
systemctl status had-antispam
```

---

# 61. Instalação central

Avaliar se o core pode ser containerizado sem quebrar:

```text
P2P
DNSBL
persistência
portas
filesystem
```

Se for seguro:

```text
Dockerfile
docker-compose.yml
```

Caso contrário:

```text
install-server.sh
```

---

# 62. Backup

Identificar exatamente:

```text
reputação
listas
clients
tickets
configuração
dados P2P
```

Criar futuramente:

```bash
had-antispam-backup
had-antispam-restore
```

---

# 63. Observabilidade

Inicialmente:

```bash
had-antispam status
```

Depois:

```text
/health
/metrics
```

Prometheus futuramente.

---

# 64. Testes obrigatórios

Cobrir:

```text
PASS
WHITE
FLAG
GREYLIST
LISTED
BLOCKED
SPAMTRAP
NXDOMAIN
INVALID
FAIL
SOFTFAIL
NEUTRAL
NONE
HOLD
```

---

# 65. Teste de indisponibilidade

Simular:

```text
serviço desligado
firewall bloqueando
timeout
DNS falhando
```

Resultado:

```text
Exim continua recebendo
Imunify continua funcionando
```

---

# 66. Teste de carga

Testar:

```text
100 consultas/s
500 consultas/s
1000 consultas/s
```

Mensurar:

```text
P50
P95
P99
erros
timeouts
CPU
RAM
```

---

# 67. Segurança

Revisar:

```text
MAIL FROM parsing
RCPT TO parsing
HELO parsing
shell injection
Perl scripts
Bash scripts
netcat
SSRF
path traversal
web panel
auth
tokens
admin endpoints
```

Nenhum dado SMTP deve ser confiável.

---

# 68. O que NÃO fazer ainda

Não:

```text
trocar Java
adicionar Redis sem necessidade
adicionar PostgreSQL sem necessidade
criar FastAPI sem necessidade
reescrever P2P
reescrever reputation
trocar protocolo
remover SPFBL external services
alterar ticket format
alterar persistência
```

Primeiro auditar.

---

# 69. Critério de sucesso da auditoria

Ao final, responder:

```text
1. Podemos usar a reputação P2P pública SPFBL?
SIM / NÃO / PARCIAL / NÃO CONFIRMADO

2. Precisa autorização?
SIM / NÃO / NÃO CONFIRMADO

3. Como entra um peer?

4. Quais portas precisam ser abertas?

5. O que é compartilhado?

6. A reputação pública pode ser usada sem alterar o core?

7. Podemos criar P2P privada HAD?

8. Podemos usar HAD P2P + SPFBL P2P?

9. Quais dependências spfbl.net precisam permanecer?

10. Quais riscos existem no fork?
```

---

# 70. Critério de sucesso do MVP

O MVP será considerado funcional quando:

```text
1. HAD AntiSpam estiver executando.
2. Um cPanel estiver autorizado.
3. Exim consultar IP, HELO, MAIL FROM e RCPT TO.
4. HAD retornar decisão.
5. PASS continuar.
6. GREYLIST gerar 451.
7. BLOCKED gerar 550.
8. FLAG seguir para Spam/Junk.
9. timeout operar em fail-open.
10. Imunify continuar funcionando.
11. reputação original funcionar.
12. tickets funcionarem.
13. P2P estiver documentado/validado.
14. instalação sobreviver ao rebuild do cPanel.
15. rollback funcionar.
```

---

# 71. Arquitetura alvo inicial

```text
                  SPFBL PUBLIC / P2P
                          |
                          v
                HAD AntiSpam Core
                          |
             +------------+------------+
             |            |            |
             v            v            v
          Valinor       Moria        Anakin
        cPanel/Exim   cPanel/Exim   cPanel/Exim
             |            |            |
             v            v            v
          Imunify      Imunify      Imunify
```

Se a rede pública não puder ser usada:

```text
                   HAD P2P PRIVADO
                          |
             +------------+------------+
             |            |            |
             v            v            v
          Valinor       Moria        Anakin
```

Se modelo híbrido for possível:

```text
                SPFBL PUBLIC P2P
                         |
                         v
                  HAD Core Node
                         |
                HAD PRIVATE P2P
                  /      |      \
                 /       |       \
            Valinor    Moria    Anakin
```

---

# 72. Princípio do produto

O HAD AntiSpam não deve virar apenas um filtro de conteúdo.

A pergunta central é:

```text
"Devo aceitar este remetente agora?"
```

antes que a mensagem seja aceita definitivamente pelo Exim.

A principal vantagem deverá ser:

```text
reputação compartilhada
+
decisão durante SMTP
+
aprendizado distribuído
```

---

# 73. Instrução final para o Codex

Antes de qualquer rebranding ou refactor grande:

```text
audite
documente
teste
prove
```

Para toda conclusão sobre P2P, reputação ou dependência externa:

```text
citar arquivo
classe
método
configuração
fluxo
```

Se algo não puder ser comprovado:

```text
marcar como NÃO CONFIRMADO
```

Não assumir comportamento apenas com base no README.

Preservar o core original até concluir a auditoria.
