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
$options = getopt("c:s:e:t:o:imnh");
function _print_help(){
    $help = <<<EOF
USO:
\$nomedoscript [-csetoh] 
OPTIONS:
-c                                           IP inicial do bloco CGNAT. ex.: 100.64.100.0
-s                                           IP inicial dos ips publicos utilizados para o CGNAT.
-e                                           IP final dos ips publicos utilizados para o CGNAT.
-t                                           Quantidade de regras por IP. ex.: 4, 8, 16, 32 (Máscara subrede)
-o                                           Nome do arquivo que será salvo as regras de CGNAT.
-m                                           Gera regras para Mikrotik RouterOS.
-i                                           Gera regras para iptables linux.
-n                                           Gera regras para nftables linux.
-h                                           Mostra essa ajuda.\n\n\n
EOF;
    exit($help);
}
function output($file, $line) {
    $output = fopen($file, 'a');
    fwrite($output, $line."\n");
    fclose($output);
}
if(isset($options['h'])){
    _print_help();
}
if(count($argv) < 7) {
    print("-- Quantidade de parametros inválidos.\n\n");
    _print_help();
}
$CGNAT_IP = ip2long($options['c']);
$CGNAT_START = ip2long($options['s']);
$CGNAT_END = ip2long($options['e']);
$CGNAT_RULES = $options['t'];
$CGNAT_RULES_COUNT = $CGNAT_RULES;
$CGNAT_OUTPUT = __DIR__ . DIRECTORY_SEPARATOR . $options['o'];
$subnet = array(
    '4096'  => '/20',
    '2048'  => '/21',
    '1024'  => '/22',
    '512'   => '/23',
    '256'   => '/24',
    '128'   => '/25',
    '64'    => '/26',
    '32'    => '/27',
    '16'    => '/28',
    '8'     => '/29',
    '4'     => '/30',
    '1'     => '/32'
);
if(!in_array($CGNAT_RULES, array_keys($subnet))) {
    exit("-- Quantidade de regras deve ter o tamanho de uma máscara de subrede.\n\n");
}
if(file_exists($CGNAT_OUTPUT)){
    unlink($CGNAT_OUTPUT);
}
$output_rules = array();
$output_jumps = array();
$x = $y = 1;
if(isset($options['m'])) {
    $output_rules[] = "/ip firewall nat";
}
for($i=0;$i<=($CGNAT_END-$CGNAT_START);++$i){
    $ip = long2ip($CGNAT_START+$i);
    $public = explode('.', $ip);
    $cgnat = explode('.', long2ip($CGNAT_IP));
    if(isset($options['m'])) {
        $output_jumps[] = "add chain=srcnat src-address=\"".long2ip($CGNAT_IP)."-".long2ip($CGNAT_IP+$CGNAT_RULES-1)."\" action=jump jump-target=\"CGNAT-{$public[2]}-{$public[3]}_OUT\"";
        $output_jumps[] = "add chain=dstnat dst-address={$ip} action=jump jump-target=\"CGNAT-{$public[2]}-{$public[3]}_IN\"";
    }elseif(isset($options['i'])){
        $output_jumps[] = "/sbin/iptables -t nat -A POSTROUTING -s ".long2ip($CGNAT_IP)."{$subnet[$CGNAT_RULES]} -j CGNAT_{$public[2]}_{$public[3]}_OUT";
        $output_jumps[] = "/sbin/iptables -t nat -A PREROUTING -d {$ip}/32 -j CGNAT_{$public[2]}_{$public[3]}_IN";
        $output_rules[] = "/sbin/iptables -t nat -N CGNAT_{$public[2]}_{$public[3]}_OUT";
        $output_rules[] = "/sbin/iptables -t nat -N CGNAT_{$public[2]}_{$public[3]}_IN";
        $output_rules[] = "/sbin/iptables -t nat -F CGNAT_{$public[2]}_{$public[3]}_OUT";
        $output_rules[] = "/sbin/iptables -t nat -F CGNAT_{$public[2]}_{$public[3]}_IN";
    }elseif(isset($options['n'])){
        $output_jumps[] = "add rule ip nat postrouting ip saddr ".long2ip($CGNAT_IP)."{$subnet[$CGNAT_RULES]} counter jump CGNAT_{$public[2]}_{$public[3]}_OUT";
        $output_jumps[] = "add rule ip nat prerouting ip daddr {$ip}/32 counter jump CGNAT_{$public[2]}_{$public[3]}_IN";
        $output_rules[] = "add chain ip nat CGNAT_{$public[2]}_{$public[3]}_OUT";
        $output_rules[] = "add chain ip nat CGNAT_{$public[2]}_{$public[3]}_IN";
        $output_rules[] = "flush chain ip nat CGNAT_{$public[2]}_{$public[3]}_OUT";
        $output_rules[] = "flush chain ip nat CGNAT_{$public[2]}_{$public[3]}_IN";
    }
    if($public[3] >= 0 && $public[3] <= 255) {
        $ports = ceil((65535-1024)/$CGNAT_RULES);
        $ports_start = 1025;
        $ports_end = $ports_start + $ports;
        for($j=$x;$j<=$CGNAT_RULES_COUNT;$j++) {
            $e_cgnat = explode('.', long2ip($CGNAT_IP));
            if($e_cgnat[3]>=0&&$e_cgnat[3]<=255) {
                if(isset($options['m'])) {
                    $output_rules[] = "add action=src-nat chain=\"CGNAT-{$public[2]}-{$public[3]}_OUT\" protocol=tcp src-address=".long2ip($CGNAT_IP)." to-addresses={$ip} to-ports={$ports_start}-{$ports_end}";
                    $output_rules[] = "add action=src-nat chain=\"CGNAT-{$public[2]}-{$public[3]}_OUT\" protocol=udp src-address=" .long2ip($CGNAT_IP)." to-addresses={$ip} to-ports={$ports_start}-{$ports_end}";
                    $output_rules[] = "add action=dst-nat chain=\"CGNAT-{$public[2]}-{$public[3]}_IN\" protocol=tcp to-addresses=".long2ip($CGNAT_IP)." src-address={$ip} dst-port={$ports_start}-{$ports_end}";
                    $output_rules[] = "add action=dst-nat chain=\"CGNAT-{$public[2]}-{$public[3]}_IN\" protocol=udp to-addresses=".long2ip($CGNAT_IP)." src-address={$ip} dst-port={$ports_start}-{$ports_end}";
                }elseif(isset($options['i'])) {
                    $output_rules[] = "/sbin/iptables -t nat -A CGNAT_{$public[2]}_{$public[3]}_OUT -s ".long2ip($CGNAT_IP)." -p tcp -j SNAT --to {$ip}:{$ports_start}-{$ports_end}";
                    $output_rules[] = "/sbin/iptables -t nat -A CGNAT_{$public[2]}_{$public[3]}_OUT -s ".long2ip($CGNAT_IP)." -p udp -j SNAT --to {$ip}:{$ports_start}-{$ports_end}";
                    $output_rules[] = "/sbin/iptables -t nat -A CGNAT_{$public[2]}_{$public[3]}_IN -d {$ip} -p tcp --dport {$ports_start}:{$ports_end} -j DNAT --to ".long2ip($CGNAT_IP);
                    $output_rules[] = "/sbin/iptables -t nat -A CGNAT_{$public[2]}_{$public[3]}_IN -d {$ip} -p udp --dport {$ports_start}:{$ports_end} -j DNAT --to ".long2ip($CGNAT_IP);
                }elseif(isset($options['n'])) {
                    $output_rules[] = "add rule ip nat CGNAT_{$public[2]}_{$public[3]}_OUT ip protocol tcp ip saddr ".long2ip($CGNAT_IP)." counter snat to {$ip}:{$ports_start}-{$ports_end}";
                    $output_rules[] = "add rule ip nat CGNAT_{$public[2]}_{$public[3]}_OUT ip protocol udp ip saddr ".long2ip($CGNAT_IP)." counter snat to {$ip}:{$ports_start}-{$ports_end}";
                    $output_rules[] = "add rule ip nat CGNAT_{$public[2]}_{$public[3]}_IN ip daddr {$ip} tcp dport {$ports_start}-{$ports_end} counter dnat to ".long2ip($CGNAT_IP);
                    $output_rules[] = "add rule ip nat CGNAT_{$public[2]}_{$public[3]}_IN ip daddr {$ip} udp dport {$ports_start}-{$ports_end} counter dnat to ".long2ip($CGNAT_IP);
                }
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
	}if(isset($options['m'])){
		$output_rules[] = "add action=src-nat chain=\"CGNAT-{$public[2]}-{$public[3]}_OUT\" to-addresses={$ip}";
	}elseif(isset($options['i'])){
		$output_rules[] = "/sbin/iptables -t nat -A CGNAT_{$public[2]}_{$public[3]}_OUT -j SNAT --to {$ip}";
    }elseif(isset($options['n'])){
		$output_rules[] = "add rule ip nat CGNAT_{$public[2]}_{$public[3]}_OUT counter snat to {$ip}";
    }
}
foreach($output_rules as $o) {
    output($CGNAT_OUTPUT, $o);
}
foreach($output_jumps as $o) {
    output($CGNAT_OUTPUT, $o);
}
