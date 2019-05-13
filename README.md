## php-cgnat-mikrotik
Script PHP para gerar regras de CGNAT para Mikrotik.
Este script foi inspirado no projeto https://github.com/helysonoliveira/cgnat-mikrotik

Este script gera regras de CGNAT com técnicas de JUMPs para diminuir o consumo de CPU do seu equipamento.

### Modo de usar:
`php cgnat.php -c 100.65.0.0 -s 198.0.2.1 -e 198.0.2.16 -t 32 -o cgnat_regras.rsc`

### Mostra a ajuda do script
`php cgnat.php -h`

### License
This is open-source software licensed under the [MIT license](https://opensource.org/licenses/MIT "MIT license").
