# Backup e restore do core nativo

O bundle nativo instala `had-antispam-backup` e `had-antispam-restore`. O backup inclui todo `/var/lib/had-antispam` — portanto `data/`, `history/`, reputação, listas, clientes, peers, usuários e `data/server.key` — e `/etc/had-antispam`, com versão da release e um manifesto de tamanhos/modos/SHA-256. O diretório transitório `.junique` fica fora do snapshot; ele é recriado pelo core ao iniciar.

O backup pausa o timer de `STORE`, faz shutdown ordenado do core para fechar a gravação sequencial do SPFBL, cria `.tar.gz` e `.tar.gz.sha256` em `/var/backups/had-antispam` e retorna o serviço/timer aos estados anteriores. Há indisponibilidade temporária das consultas durante o snapshot. Os arquivos e diretório são privados ao root (`0600`/`0700`); os artefatos contêm a chave de tickets e os dados completos da instalação.

```bash
sudo had-antispam-backup
sudo had-antispam-restore /var/backups/had-antispam/spfbl-AAAAMMDDTHHMMSSZ-ID.tar.gz --dry-run
sudo had-antispam-restore /var/backups/had-antispam/spfbl-AAAAMMDDTHHMMSSZ-ID.tar.gz --yes
```

O restore exige `--yes`, valida checksum lateral e manifesto interno, recusa caminhos, links e arquivos especiais, e só aceita a mesma versão instalada. Antes de substituir estado/configuração, cria um snapshot `pre-restore-*`. Instala os dados em diretórios de estágio no mesmo filesystem, normaliza propriedade para `hadantispam`/root, troca os diretórios e inicia o core se ele estava ativo. Falha ao iniciar dispara rollback para os diretórios anteriores; o snapshot `pre-restore` também é preservado.

Guarde o `.tar.gz` junto com seu `.sha256`. A soma detecta corrupção acidental; ela não autentica a origem se alguém puder substituir ambos. Para cópia externa, use canal confiável e criptografia sob controle do operador. Este pacote não restaura o sistema operacional, units systemd, Nginx, firewall do provedor, DNS nem logs de `/var/log/had-antispam`; mantenha backup de infraestrutura separado.

## Verificação executada

`test_backup_restore.py`: sete testes cobrem snapshot, arquivos e chave, exclusão do lock transitório, checksum, path traversal, versão incompatível, dry-run e rollback após falha simulada de start. `core_restore_smoke.py` inicializa o JAR da release final `1.1.8-had-20261002` em container descartável com `--network none`, sem dados ou chaves reais; grava cliente, CIDR e dicionário sintéticos, faz backup, altera o estado, restaura e comprova após o novo start que os dados anteriores e a chave persistem e as alterações posteriores desapareceram. O manifesto do ensaio incluiu 19 arquivos; SHA-256 do snapshot: `709622c711ae05508fab7993dec3270c7620092b967a1508c158fe5c275f5410`.

Os utilitários estão instalados na VM central pela release `1.1.9-had-20261002`. Backup operacional `spfbl-20261002T090125Z-c48e4904.tar.gz` foi criado e validado: 39 arquivos, checksum `b1853ce9137666209aab0eb54d85b84f7e92748055caea378b8a7130fc48d117`, verificação lateral `OK` e restore `--dry-run` aprovado. Bundle instalado: `.audit/native-bundle/had-antispam-1.1.9-had-20261002.tar.gz`, SHA-256 `10de1237a3b00997b5c1112786558a57b3905fd660d0d9f92b32ab2a930d8b23`. Copiar para destino separado, testar restore fora da VM de produção, comprovar RPO/RTO e compatibilidade entre releases continuam pendentes.
