# Firewall pelo painel admin

O pacote nativo SpamFox oferece gestão dos IPs/CIDRs autorizados a consultar a TCP 9877 em `https://matrix.example.com/admin/firewall/`. Entre primeiro com a conta administradora configurada no core e abra **Firewall** no menu de Administração do core. Usuários comuns e postmasters não têm acesso a essa área.

## Operações

- **Adicionar IP/CIDR:** informe o endereço público de saída do MTA e uma descrição opcional.
- **Editar:** abra **Editar / remover**, altere o endereço ou a descrição e salve.
- **Remover:** confirme a remoção do registro. Remover o último endereço deixa todas as consultas externas bloqueadas.
- **Reaplicar regras:** sincroniza o firewall carregado com a lista persistida, por exemplo após editar o arquivo pelo terminal.

A lista é o próprio `/etc/spamfox/allowed-cpanels.txt`. Cada alteração aplica as regras e persiste o arquivo. Formulários antigos são recusados quando outra edição já alterou a lista. São aceitos IPv4 e IPv6, até 1024 registros, com descrições de até 160 caracteres. Redes `/0` são recusadas. Ao remover um registro, verifique se outro CIDR sobreposto continua liberando o mesmo IP.

A liberação de rede complementa o cadastro nativo **CLIENT**: o servidor também precisa estar cadastrado no core para consultar o SPFBL. Esse CRUD administra somente a tabela nftables `inet spamfox` na VM central. Ele mantém ADMIN TCP 9875 e HTTP TCP 8080 bloqueados externamente e não altera SSH, CSF dos cPanels ou outras tabelas da VM.

## Instalação e privilégios

O instalador nativo inclui e habilita `spamfox-firewall-admin.service`. O core continua como usuário `spamfox`, sem root e sem permissão para editar a configuração diretamente. O serviço auxiliar recebe somente operações predefinidas por `/run/spamfox-firewall/control.sock`, um socket Unix acessível apenas a root e ao usuário do core. A API não aceita comandos de shell, portas ou caminhos arbitrários.

O auxiliar executa como root com a capability `CAP_NET_ADMIN`, acesso de escrita restrito à configuração e backups, e sem listener TCP público. O processo web valida a sessão administrativa, HTTPS e um token CSRF antes de chamar o auxiliar. Uma falha de aplicação preserva o arquivo anterior; se a gravação do arquivo falhar depois da aplicação das regras, o auxiliar tenta reaplicar a configuração anterior e informa explicitamente se o rollback falhar.

Ao iniciar, o auxiliar reaplica a lista persistida para reconciliar uma eventual interrupção entre a atualização do kernel e a gravação do arquivo.

O Nginx usa o mesmo proxy do painel SPFBL. Não é necessário publicar outra porta ou criar um proxy para o socket. A instalação exige ao menos um IP autorizado inicialmente; depois, uma lista vazia intencional continua bloqueando consultas após reiniciar a VM.

## Auditoria e recuperação

As alterações bem-sucedidas registram o administrador, a ação e os endereços envolvidos:

```bash
systemctl status spamfox-firewall-admin.service
journalctl -u spamfox-firewall-admin.service --since today --no-pager
```

Antes de mudar a lista, o auxiliar guarda uma cópia privada em `/var/backups/spamfox/firewall/`. Depois de uma alteração concluída, mantém as 50 cópias mais recentes; tentativas que falharam também podem deixar backups para diagnóstico. Não há mensagens `.eml` nesses arquivos.

Para recuperar manualmente uma versão da lista, confira o arquivo de backup, copie-o como root para `/etc/spamfox/allowed-cpanels.txt` e reaplique:

```bash
systemctl restart spamfox-firewall.service
```

Confira o status no painel após a recuperação. Alterações feitas por ferramentas externas podem produzir divergência; a página informa se a tabela está carregada e se corresponde à lista persistida.

## Testes de desenvolvimento

O teste abaixo cria um namespace de rede isolado para exercitar o nftables real, sem alterar as regras de rede do host. Exige Linux com namespaces de usuário habilitados, Python 3 e nftables:

```bash
bash packaging/native/test-firewall-admin.sh
```

Os testes HTTP de autenticação administrativa e CSRF fazem parte de `bash packaging/native/test-content-bayes.sh`. Os testes de falha, rollback e socket local ficam em `python3 -m unittest discover -s packaging/native -p 'test_firewall*.py'`.
