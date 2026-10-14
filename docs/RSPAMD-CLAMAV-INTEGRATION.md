# ClamAV no fluxo central Rspamd

O Enhance SP01 já envia uma cópia após a fila para o gateway central Rspamd. O ClamAV foi integrado nessa VM central, `antispam.hadcloud.srv.br` (`151.242.41.35`), para que os anexos enviados pelos monitores sejam verificados sem instalar outro daemon pesado no SP01. O coletor, o Postfix, o SPFBL e a entrega não foram alterados.

O piloto usa os bancos oficiais atualizados pelo `freshclam` e adiciona ao resultado os símbolos `CLAM_VIRUS`, `CLAM_VIRUS_FAIL`, `CLAM_VIRUS_ENCRYPTED` e `CLAM_VIRUS_MACRO`. O relatório `had-content-scan-report` agrega esses símbolos por cliente sem mostrar remetentes, assuntos, nomes de malware ou conteúdo. `CLAM_VIRUS` está com peso zero e sem ação de rejeição; esta etapa detecta e registra, mas a cópia monitorada é analisada depois que o Postfix já aceitou e entregou a mensagem.

As bases adicionais usadas pelo instalador cPanel (`https://matrix.spfbl.net/spfbl.hsb`, `spfbl.ign2` e `cpanel.ign2`) expiraram por timeout de rede a partir das VMs central e SP01 na validação de 11/10/2026. Elas não foram habilitadas nem substituídas por uma cópia local. A instalação atual mantém apenas os bancos oficiais do ClamAV; reavalie os feeds SPFBL quando o endpoint voltar a responder.

O instalador suporta Ubuntu/Debian com Rspamd ativo e pelo menos 3 GiB de memória disponível. No servidor central:

```bash
bash install-clamav-antivirus.sh --check
bash install-clamav-antivirus.sh --install
bash install-clamav-antivirus.sh --repair
bash install-clamav-antivirus.sh --rollback
```

`--install` é para uma instalação nova; `--repair` reaplica apenas os parâmetros deste piloto; `--rollback` restaura os arquivos existentes antes da instalação e desativa os serviços, mantendo os pacotes baixados. Na VM, o gerenciador também está disponível como `had-clamav-rspamd`. O daemon usa socket Unix local, duas threads de varredura e `ConcurrentDatabaseReload no` para reduzir o pico de RAM durante atualização de assinaturas.

Para verificar uma detecção positiva sem armazenar um arquivo de teste infectado, use o recurso `eicar_fake_pattern` do módulo Rspamd. O script abaixo altera a configuração temporariamente, reinicia o Rspamd, envia uma mensagem sintética a `127.0.0.1:11333/checkv2`, exige o símbolo `CLAM_VIRUS` e restaura a configuração original:

```bash
python3 tools/test_rspamd_clamav_probe.py --confirm-temporary-rspamd-restart
```

O daemon ClamAV deve permanecer no servidor central enquanto o SP01 estiver com menos de 3 GiB de memória disponível. O ClamAV usa mais memória ao recarregar bases; o guia oficial recomenda pelo menos 3 GiB e documenta o pico de recarga concorrente. Se a etapa futura precisar rejeitar vírus antes da fila, ela deve ser validada separadamente no Milter e só então ativar uma ação de rejeição.
