# Coleta técnica e feedback manual no Grupo Guedes — 2026-10-03

## Validação executada

- SSH por chave com verificação estrita do host; Exim 4.100.1 e Python 3.6.8.
- Um bundle sem credenciais foi extraído em `/var/tmp/had-antispam-verify.gk86eJ`. Os 86 testes cPanel passaram no Python do próprio servidor.
- O harness usou configuração Exim descartável, sockets/core falsos e fake SMTP: RCPT, MAIL FROM nulo, RSET, múltiplos destinatários, socket ausente/timeout, passagem de ticket a DATA, cabeçalho restrito a destinatário único e remoção do cabeçalho forjado passaram. CLI manual, HMAC de auditoria e comando único SPAM também passaram contra core descartável. Nenhuma mensagem foi enfileirada ou entregue.

## Atualização aplicada

- Adapter, módulo de sinais técnicos e CLI `/usr/local/sbin/had-antispam-feedback` instalados. Os hooks RCPT e DATA/HEADER passaram reconstrução, teste fake SMTP da configuração ativa e reinício final do Exim. Os dois healthchecks confirmaram os hooks na fonte cPanel e no Exim gerado.
- A instalação confirmou 21 campos na chamada DATA local. Os dez sinais são allowlisted; por enquanto, somente a categoria SPFBL e os booleanos de autenticação/TLS têm fonte habilitada. SPF/DKIM/DMARC/Rspamd/rDNS continuam desconhecidos até observar cálculo e ordem reais. As expansões opcionais foram aceitas pelo Exim, mas não houve valor em transação real comprovado; não existe condição `spf =` ativa na configuração examinada.
- `/etc/had-antispam/signals-hmac.key` é root-owned, grupo mail, modo 0640, em diretório root:mail 0750. A leitura foi validada sob `mailnull:mail`, a identidade explícita da unit. O CLI permanece root-only; a configuração existente foi preservada.
- Os módulos instalados e o CLI coincidem byte a byte com o bundle testado. Exim e `had-antispam-client.service` estão ativos. O CLI gerou relatório vazio a partir de stdin vazio, validando imports/execução sem transmitir feedback.
- As ACLs HAD permanecem MONITOR/fail-open. O novo ticket só entra em mensagem SMTP não autenticada com um destinatário; feedback exige revisão e confirmação manual. Nenhuma chamada Jev ou nova decisão automática foi habilitada. A ACL upstream SPFBL existente mantém sua política anterior.

## Reversão e ocorrências

As tentativas iniciais foram recusadas pelo teste fake SMTP porque a caixa antiga não existia ou porque o domínio escolhido tinha entrega externa. Não foi relaxada a proteção contra relay: selecionamos finalmente uma caixa existente cujo domínio pertence a `/etc/localdomains`.

O primeiro snapshot operacional usou um caminho incorreto para o hook RCPT. A correção recuperou o bloco original a partir do Exim salvo; a reconstrução coincidiu tanto com `managed_block_sha256` quanto com `hook_sha256_installed` do manifesto original. O Exim gerado também foi restaurado exatamente ao SHA-256 anterior `6a5dfea030965f03916a2974f3991b5f36a744fd818e835bcb9164c48f3a4ed7` e reiniciado antes das novas tentativas. O snapshot final usa o caminho correto `ACL_RECIPIENT_BLOCK/custom_begin_recipient`, inclui hooks e estados dos managers e preserva permissões.

Snapshot privado da atualização concluída: `/var/lib/had-antispam-client/upgrade-20261003-signals-validated`. O diretório é root-only e contém dados/configurações privados; não foi copiado ao repositório.

## Limites e próxima prova

Ainda falta uma mensagem SMTP remota real com ticket, captura técnica correlacionada e um rótulo humano aceito. Os testes falsos não comprovam mudança de contador ou reputação de produção. O dataset exportador está instalado, mas não existe conjunto calibrado ou medição de precisão/recall; o gate Jev permanece sem fonte de confiança e desconectado.
