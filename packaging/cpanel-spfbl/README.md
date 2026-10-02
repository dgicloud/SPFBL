# HADCloud SPFBL para cPanel

Instalador baseado no script oficial client/spfbl.cpanel.sh do projeto [SPFBL](https://github.com/leonamp/SPFBL), versão 1.4 no commit de referência 7b0232e96f16faca151340b80c418838a800237f.

A adaptação preserva a instalação Exim/ClamAV do script oficial e direciona as consultas para o servidor SPFBL da HADCloud (151.242.41.35:9877). O endpoint é aplicado ao cliente SPFBL baixado tanto na instalação quanto em update, ao spamd_address do Exim e ao atualizador de firewall gerado pelo SPFBL. As ACLs Exim e o core SPFBL permanecem upstream.

O script mantém a licença e os avisos de copyright do upstream. O instalador ainda baixa arquivos upstream do SPFBL e do clamav-unofficial-sigs durante a execução.

## Pré-requisitos de rede

- cPanel/WHM funcional, execução como root.
- Saída TCP 9877 liberada no firewall de cada servidor cPanel.
- O firewall do servidor HADCloud deve aceitar TCP 9877 somente dos IPs de saída dos cPanels autorizados.
- A porta administrativa 9875 não é necessária para o fluxo de consulta de mensagens dos cPanels e deve permanecer restrita no servidor SPFBL. Os subcomandos administrativos do cliente oficial que usam 9875 não fazem parte do fluxo de e-mail.
- Instalação/atualização e remoção seguem o comportamento do instalador upstream e alteram a configuração do Exim, ClamAV e firewall do cPanel.

## Instalação

Esta adaptação é publicada na branch `hadcloud-cpanel-installer` do fork [dgicloud/SPFBL](https://github.com/dgicloud/SPFBL):

~~~bash
curl -fsSL https://raw.githubusercontent.com/dgicloud/SPFBL/hadcloud-cpanel-installer/packaging/cpanel-spfbl/spfbl.cpanel.sh -o /root/spfbl.cpanel.sh
bash /root/spfbl.cpanel.sh install
~~~

Para atualizar uma instalação existente:

~~~bash
bash /root/spfbl.cpanel.sh update
~~~

Para remover:

~~~bash
bash /root/spfbl.cpanel.sh uninstall
~~~

Para validar a conectividade e a versão após a instalação:

~~~bash
/usr/local/bin/spfbl version
~~~

O comando version deve retornar uma versão SPFBL-.... Ele verifica o endpoint TCP 9877 configurado no cliente.

## Atualização do upstream

O script baixa as ACLs e o cliente oficial do branch master do upstream durante install/update. Após cada download do cliente, aplica o endpoint HADCloud somente se encontrar exatamente uma linha IP_SERVIDOR reconhecida. O atualizador de firewall também só é alterado quando encontra exatamente uma ocorrência do IP upstream esperado. Se a estrutura upstream mudar, o script interrompe essa etapa para evitar deixar um endereço ou patch ambíguo.

Revise este instalador contra novas versões do upstream antes de promovê-las aos demais cPanels.
