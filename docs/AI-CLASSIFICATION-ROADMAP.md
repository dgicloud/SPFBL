# Plano simples de classificação SpamFox

O SpamFox usa duas camadas de classificação, cada uma com uma função clara. O core SPFBL permanece upstream e decide reputação de IP, SPF, HELO, remetente e rede P2P durante a sessão SMTP. O Rspamd central analisa uma cópia do conteúdo e usa o Bayes nativo para aprender mensagens elegíveis. Não há integração com provedor externo de IA.

## Fluxo atual

1. O cliente SPFBL em Exim/Postfix consulta o core durante SMTP. As decisões do core continuam sendo a proteção de reputação que pode afetar a aceitação da mensagem.
2. O coletor envia uma cópia da mensagem ao gateway central do Rspamd depois do aceite. Esse caminho é de observação e aprendizagem: falha, lotação ou timeout não mudam a entrega original.
3. Rspamd aplica autotreino nativo somente a mensagens inscritas, com metadados SMTP válidos, não autenticadas e em faixas conservadoras de score. O Bayes só participa depois do mínimo configurado por classe.
4. Para spam de alta confiança, se houver exatamente um ticket SPFBL válido e destinatário único, o gateway pode enviar `SPAM <ticket>` ao core. O core recebe o ticket; não recebe corpo, assunto, score Bayes nem uma nova política de bloqueio.
5. A WebUI nativa do Rspamd serve para histórico, diagnóstico e aprendizado manual pontual de arquivos `.eml`.

## Limites de comportamento

O coletor after-queue não bloqueia retroativamente a mensagem que já foi aceita. A denúncia SPFBL atualiza reputação para consultas futuras. A marcação síncrona está limitada às caixas canário configuradas; quarentena e rejeição por conteúdo permanecem desativadas até passar uma avaliação independente de falsos positivos.

O ClamAV instalado fica na VM central e é chamado pelo Rspamd. Conforme a evidência de 11/10/2026, ele usa assinaturas oficiais e `CLAM_VIRUS` tem peso zero; portanto detecta para observabilidade, sem rejeitar mensagens. Não instalar ClamAV local nos Postfix.

## Estado documentado e trabalho restante

A evidência de 09/10/2026 registrou 333 análises reais em uma janela, cinco denúncias SPAM aceitas pelo core e aumento dos contadores Bayes para 1.158 SPAM e 1.265 HAM. Esses números são um retrato daquela janela, não um estado confirmado de hoje. Leia [a evidência de aprendizagem e feedback](evidence/rspamd-spfbl-learning-pipeline-20261009.md) e atualize os números com uma checagem ao vivo antes de mudar políticas.

- Atualizar o estado operacional de Exim, Postfix, gateway, Rspamd, Redis, autotreino e clientes inscritos.
- Confirmar que mensagens naturais das caixas canário recebem os cabeçalhos esperados e que os registros podem ser encontrados no histórico do Rspamd.
- Antes de habilitar quarentena ou rejeição, preparar um holdout separado por origem e executar o avaliador e os limites de qualidade em [`RSPAMD-SUPERVISED-PILOT.md`](RSPAMD-SUPERVISED-PILOT.md).
- Fazer cópia externa dos backups do core e do modelo Redis e ensaiar a restauração em staging; ver [`BACKUP-RESTORE.md`](BACKUP-RESTORE.md).
- Atualizar os relatórios gerais de estado, que ainda contêm snapshots de 02–03/10, usando as evidências operacionais mais recentes.

Este plano mantém o fluxo pequeno: SPFBL para decisões de envelope, Rspamd/Bayes para análise de conteúdo e feedback limitado por ticket. Qualquer nova camada só deve ser adicionada se melhorar a classificação medida sem aumentar o risco de falso positivo ou a complexidade de instalação dos MTAs.
