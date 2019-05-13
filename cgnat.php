#!/usr/bin/env php
<?php

/**
 * PHP CGNAT MIKROTIK
 *
 * @author     Diorges Rocha <diorges@gis.net.br>
 * @copyright  (C) 2019 Diorges Rocha
 *
 */

chdir(dirname($argv[0]));

$options = getopt("c:s:e:t:o:h");

if(isset($options['h'])){
    $help = <<<EOF
USO:
\$nomedoscript [-csetoh] 

OPTIONS:
-c                                           IP inicial do bloco CGNAT. ex.: 100.64.100.0
-s                                           IP inicial dos ips publicos utilizados para o CGNAT.
-e                                           IP final dos ips publicos utilizados para o CGNAT.
-t                                           Quantidade de regras por IP. ex.: 32
-o                                           Nome do arquivo que será salvo as regras de CGNAT.
-h                                           Mostra essa ajuda.\n\n\n
EOF;

    exit($help);
}

if(count($argv) < 6) {
    exit("Quantidade de parametros inválidos.\n");
}

function output($file, $line) {
    $output = fopen($file, 'a');
    fwrite($output, $line."\n");
    fclose($output);
}

$CGNAT_IP = ip2long($options['c']);
$CGNAT_START = ip2long($options['s']);
$CGNAT_END = ip2long($options['e']);
$CGNAT_RULES = $options['t'];
$CGNAT_RULES_COUNT = $CGNAT_RULES;
$CGNAT_OUTPUT = __DIR__ . DIRECTORY_SEPARATOR . $options['o'];

$output_rules = array();
$output_jumps = array();
$x = $y = 1;
$output_rules[] = "/ip firewall nat";
for($i=1;$i<=($CGNAT_END-$CGNAT_START);$i++){
    $ip = long2ip($CGNAT_START+$i);
    $public = explode('.', $ip);
    $cgnat = explode('.', long2ip($CGNAT_IP));
    $output_jumps[] = "add chain=srcnat src-address=\"".long2ip($CGNAT_IP)."-{$cgnat[0]}.{$cgnat[1]}.{$cgnat[2]}.".(($cgnat[3]+$CGNAT_RULES)-1)."\" action=jump jump-target=\"CGNAT-{$public[2]}-{$public[3]}_OUT\"";
    $output_jumps[] = "add chain=dstnat dst-address={$ip} action=jump jump-target=\"CGNAT-{$public[2]}-{$public[3]}_IN\"";
    if($public[3] >= 0 && $public[3] <= 255) {
        $ports = ceil((65535-1024)/$CGNAT_RULES);
        $ports_start = 1025;
        $ports_end = $ports_start + $ports;
        for($j=$x;$j<=$CGNAT_RULES_COUNT;$j++) {
            $e_cgnat = explode('.', long2ip($CGNAT_IP));
            if($e_cgnat[3]>=0&&$e_cgnat[3]<=255) {
                $output_rules[] = "add action=src-nat chain=\"CGNAT-{$public[2]}-{$public[3]}_OUT\" protocol=tcp src-address=".long2ip($CGNAT_IP)." to-addresses={$ip} to-ports={$ports_start}-{$ports_end}";
                $output_rules[] = "add action=src-nat chain=\"CGNAT-{$public[2]}-{$public[3]}_OUT\" protocol=udp src-address=".long2ip($CGNAT_IP)." to-addresses={$ip} to-ports={$ports_start}-{$ports_end}";
                $output_rules[] = "add action=src-nat chain=\"CGNAT-{$public[2]}-{$public[3]}_OUT\" src-address=".long2ip($CGNAT_IP)." to-addresses={$ip}";
                $output_rules[] = "add action=dst-nat chain=\"CGNAT-{$public[2]}-{$public[3]}_IN\" protocol=tcp to-addresses=".long2ip($CGNAT_IP)." src-address={$ip} dst-port={$ports_start}-{$ports_end}";
                $output_rules[] = "add action=dst-nat chain=\"CGNAT-{$public[2]}-{$public[3]}_IN\" protocol=udp to-addresses=".long2ip($CGNAT_IP)." src-address={$ip} dst-port={$ports_start}-{$ports_end}";
                $ports_start = $ports_end + 1;
                $ports_end += $ports;
                if($ports_end > 65535){
                    $ports_end = 65535;
                }
            }
            $CGNAT_IP++;
            $y++;
        }
        $x=$y;
        $CGNAT_RULES_COUNT+=$CGNAT_RULES;
    }
}

foreach($output_rules as $o) {
    output($CGNAT_OUTPUT, $o);
}

foreach($output_jumps as $o) {
    output($CGNAT_OUTPUT, $o);
}
