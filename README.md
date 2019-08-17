## php-cgnat
Script PHP para gerar regras de CGNAT

Este script foi inspirado no projeto https://github.com/helysonoliveira/cgnat-mikrotik

### Sistemas suportados
- RouterOS (-m)
- iptables (-i)
- nftables (-n)
- ~~Huawei~~
- ~~Juniper~~
- ~~Cisco~~

Este script gera regras de CGNAT com técnicas de JUMPs para diminuir o consumo de CPU do seu equipamento.

### Modo de usar:
- RouterOS

`php cgnat.php -c 100.65.0.0 -s 198.0.2.1 -e 198.0.2.16 -t 32 -o arquivo_de_saida.rsc -m`

- iptables

`php cgnat.php -c 100.65.0.0 -s 198.0.2.1 -e 198.0.2.16 -t 32 -o arquivo_de_saida -i`

- nftables

`php cgnat.php -c 100.65.0.0 -s 198.0.2.1 -e 198.0.2.16 -t 32 -o arquivo_de_saida.nft -n`

### Mostra a ajuda do script
`php cgnat.php -h`

### License
This is open-source software licensed under the [MIT license](https://opensource.org/licenses/MIT "MIT license").
