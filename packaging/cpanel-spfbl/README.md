# HAD Cloud SpamFox para cPanel

Instalador baseado no script oficial client/spfbl.cpanel.sh do projeto [SPFBL](https://github.com/leonamp/SPFBL), versão 1.4 no commit de referência 7b0232e96f16faca151340b80c418838a800237f.

A adaptação preserva a instalação Exim/ClamAV do script oficial e direciona as consultas para o servidor SPFBL da HADCloud (151.242.41.35:9877). O endpoint é aplicado ao cliente SPFBL baixado tanto na instalação quanto em update, ao spamd_address do Exim e ao atualizador de firewall gerado pelo SPFBL. As ACLs HAD de destinatário e análise de mensagem vêm do branch do fork e apresentam respostas de cliente como SpamFox (SFOX); a lógica, os comandos, o protocolo, o core SPFBL e as atribuições permanecem preservados.

O script mantém a licença e os avisos de copyright do upstream. O instalador ainda baixa o cliente SPFBL e arquivos do clamav-unofficial-sigs durante a execução; as duas ACLs personalizadas de resultados são obtidas do fork HAD.

## Pré-requisitos de rede

- cPanel/WHM funcional, execução como root.
- Saída TCP 9877 liberada no firewall de cada servidor cPanel.
- O firewall do servidor HADCloud deve aceitar TCP 9877 somente dos IPs de saída dos cPanels autorizados.
- A porta administrativa 9875 não é necessária para o fluxo de consulta de mensagens dos cPanels e deve permanecer restrita no servidor SPFBL. Os subcomandos administrativos do cliente oficial que usam 9875 não fazem parte do fluxo de e-mail.
- Instalação/atualização e remoção seguem o comportamento do instalador upstream e alteram a configuração do Exim, ClamAV e firewall do cPanel.

## Instalação

Esta adaptação é publicada na branch `hadcloud-cpanel-installer` do fork [dgicloud/SPFBL](https://github.com/dgicloud/SPFBL):

~~~bash
curl -fsSL https://raw.githubusercontent.com/dgicloud/SPFBL/hadcloud-cpanel-installer/packaging/cpanel-spfbl/spamfox.cpanel.sh -o /root/spamfox.cpanel.sh
bash /root/spamfox.cpanel.sh install
~~~

Para atualizar uma instalação existente:

~~~bash
bash /root/spamfox.cpanel.sh update
~~~

Para remover:

~~~bash
bash /root/spamfox.cpanel.sh uninstall
~~~

Para validar a conectividade e a versão após a instalação:

~~~bash
/usr/local/bin/spfbl version
~~~

O comando version deve retornar uma versão SPFBL-.... Ele verifica o endpoint TCP 9877 configurado no cliente.

## Atualização do upstream

O script baixa o cliente oficial do branch master do upstream durante install/update e obtém as ACLs HAD de resultados do branch `hadcloud-cpanel-installer` do fork. Após cada download do cliente, aplica o endpoint HADCloud somente se encontrar exatamente uma linha IP_SERVIDOR reconhecida. O atualizador de firewall também só é alterado quando encontra exatamente uma ocorrência do IP upstream esperado. Se a estrutura upstream mudar, o script interrompe essa etapa para evitar deixar um endereço ou patch ambíguo.

Revise este instalador contra novas versões do upstream antes de promovê-las aos demais cPanels.
