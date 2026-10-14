# Base upstream e diferenças HAD

Data de verificação: 2026-10-01.

| Item | Estado verificado |
|---|---|
| Upstream | `https://github.com/leonamp/SPFBL.git` |
| Branch original | `master` |
| Commit base | `7b0232e96f16faca151340b80c418838a800237f` |
| Commit original | 2026-08-27, `Update spfbl.directadmin.sh` |
| Branch local | `main`, inicialmente rastreando `upstream/master` |
| Histórico | Fetch do histórico upstream, não snapshot de arquivos isolados |
| Fork remoto HAD | URL de origin prevista/configurável conforme escopo; criação, push e publicação NÃO CONFIRMADOS |

## Diferença funcional

O core e os demais arquivos upstream foram preservados, com uma exceção visual pequena em `src/net/spfbl/service/ServerHTTP.java`: a coluna Entrega agora usa os indicadores do painel original e diferencia rejeição por banimento. Bibliotecas, binário distribuído, dados, scripts e licença originais continuam preservados.

As adições HAD até esta etapa são o escopo fornecido, documentação em `docs/`, evidências de laboratório, ferramentas em `packaging/audit/`, ambiente/testes Exim descartável em `packaging/dev/` e protótipo MONITOR/socket local em `integrations/cpanel/`. Os arquivos estão presentes no working tree; isso não implica commit, release ou publicação remota. `.audit/` contém estado/build local e foi excluído por `.git/info/exclude`, sem modificar arquivos upstream.

`packaging/audit/build-upstream.sh` compila as 59 fontes para um JAR separado; esse build inclui a alteração de apresentação citada acima e nunca substitui `dist/SPFBL.jar`. `ReputationAudit.java` testa as classes reais. O helper SSH usa senha somente na memória e não inclui credenciais na documentação. Testes de segurança usam um container separado, rede interna sem acesso público e artifacts geridos pelo scan Codex Security.

## Rastreabilidade futura

Antes de mudanças funcionais: registrar o commit base, a superfície alterada, razão, impactos no protocolo/persistência/P2P e testes. Separar adapter cPanel de core facilita atualização upstream. Não substituir domínios de terceiros em dados históricos por HAD.

Uma atualização deve ocorrer em branch própria, examinando diff e conflitos, recompilando e reexecutando os testes. Não executar merge automático de upstream na instalação ativa. A semântica do binário distribuído e a compatibilidade da persistência também precisam ser verificadas, não só o sucesso do merge.

Licença e copyright originais permanecem em `licence.txt` e nos arquivos fonte. Rebranding ainda não foi aplicado.
