# Backup e restore do core nativo

O bundle instala `spamfox-backup` e `spamfox-restore`. O backup inclui o estado do core em `/var/lib/spamfox` e a configuração operacional em `/etc/spamfox`. O lock transitório `.junique` fica fora do snapshot porque é recriado pelo core ao iniciar. Backups gerados por versões anteriores continuam aceitos pelo restore.

O backup pausa o timer de persistência, faz o encerramento ordenado do core e cria um arquivo `.tar.gz` com checksum lateral em `/var/backups/spamfox`. As consultas ficam indisponíveis durante o snapshot. Os arquivos são privados ao root (`0600`/`0700`) porque incluem a chave de tickets e dados completos da instalação.

```bash
sudo spamfox-backup
sudo spamfox-restore /var/backups/spamfox/spfbl-AAAAMMDDTHHMMSSZ-ID.tar.gz --dry-run
sudo spamfox-restore /var/backups/spamfox/spfbl-AAAAMMDDTHHMMSSZ-ID.tar.gz --yes
```

O restore exige `--yes`, valida checksum e manifesto, recusa caminhos e arquivos especiais e só aceita uma versão compatível. Antes de substituir estado ou configuração, cria um snapshot `pre-restore-*`. Uma falha ao iniciar o core restaura os diretórios anteriores.

Guarde o `.tar.gz` junto com o `.sha256`. O checksum detecta corrupção acidental, mas não autentica a origem se ambos puderem ser substituídos. Para cópia externa, use um canal confiável e criptografia sob controle do operador. O pacote não restaura o sistema operacional, units systemd, Nginx, firewall do provedor, DNS ou logs; mantenha backup de infraestrutura separado.

Os testes `test_backup_restore.py` cobrem consistência do snapshot, chave de tickets, exclusão do lock transitório, checksum, path traversal, incompatibilidade de versão, dry-run e rollback após falha simulada de inicialização.
