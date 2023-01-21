<?php
define('BIND_IP', '127.0.0.1');
define('BIND_PORT', 53);
define('QUERY_TYPES', [
	1 => 'A',
	2 => 'NS',
	5 => 'CNAME',
	6 => 'SOA',
	12 => 'PTR',
	15 => 'MX',
	16 => 'TXT',
	28 => 'AAAA',
	41 => 'OPT',
	252 => 'AXFR',
	255 => 'ANY',
	18 => 'AFSDB',
	42 => 'APL',
	257 => 'CAA',
	60 => 'CDNSKEY',
	59 => 'CDS',
	37 => 'CERT',
	49 => 'DHCID',
	32769 => 'DLV',
	48 => 'DNSKEY',
	43 => 'DS',
	45 => 'IPSECKEY',
	25 => 'KEY',
	36 => 'KX',
	29 => 'LOC',
	35 => 'NAPTR',
	47 => 'NSEC',
	50 => 'NSEC3',
	51 => 'NSEC3PARAM',
	46 => 'RRSIG',
	17 => 'RP',
	24 => 'SIG',
	33 => 'SRV',
	44 => 'SSHFP',
	32768 => 'TA',
	249 => 'TKEY',
	52 => 'TLSA',
	250 => 'TSIG',
	256 => 'URI',
	39 => 'DNAME',
]);
$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

if (!$socket) {
	printf('Cannot create socket (socket error: %s).', socket_strerror(socket_last_error($socket)));
	exit;
}

if (!socket_bind($socket, BIND_IP, BIND_PORT)) {
	printf('Cannot bind socket to %s:%d (socket error: %s).', BIND_IP, BIND_PORT, socket_strerror(socket_last_error($socket)));
	exit;
}

while (true) {
	$buffer = $ip = $port = null;

	if (!socket_recvfrom($socket, $buffer, 512, null, $ip, $port)) {
		printf('Cannot read from socket ip: %s, port: %d (socket error: %s).', $ip, $port, socket_strerror(socket_last_error($socket)));
	} else {
		$response = handle_query($buffer, $question);
		//PRINT
		foreach($question as $query){
			printf("[%s] %s\n", QUERY_TYPES[$query['qtype']], $query['qname']);
		}
		//END PRINT
		if (!socket_sendto($socket, $response, strlen($response), 0, $ip, $port)) {
			printf('Cannot send reponse to socket ip: %s, port: %d (socket error: %s).', $ip, $port, socket_strerror(socket_last_error($socket)));
		}
	}
}
echo "Done\n";

function handle_query($buffer, &$question){
	$data = unpack('npacket_id/nflags/nqdcount/nancount/nnscount/narcount', $buffer);
	$flags = decode_flags($data['flags']);
	$offset = 12;

	$question = decode_question($buffer, $offset, $data['qdcount']);

	$flags['rcode'] = 3;
	$flags['qr'] = 1;
	$flags['ra'] = 0;

	$qdcount = count($question);

	$response = pack('nnnnnn', $data['packet_id'], encode_flags($flags), $qdcount, 0, 0, 0);
	$response .= encode_question($question, strlen($response));

	return $response;
}

function decode_flags($flags){
	return [
		'qr'	 => $flags >> 15 & 0x1,
		'opcode' => $flags >> 11 & 0xf,
		'aa'	 => $flags >> 10 & 0x1,
		'tc'	 => $flags >> 9 & 0x1,
		'rd'	 => $flags >> 8 & 0x1,
		'ra'	 => $flags >> 7 & 0x1,
		'z'		 => $flags >> 4 & 0x7,
		'rcode'	 => $flags & 0xf,
	];
}

function encode_flags($flags){
	$val = 0;

	$val |= ($flags['qr'] & 0x1) << 15;
	$val |= ($flags['opcode'] & 0xf) << 11;
	$val |= ($flags['aa'] & 0x1) << 10;
	$val |= ($flags['tc'] & 0x1) << 9;
	$val |= ($flags['rd'] & 0x1) << 8;
	$val |= ($flags['ra'] & 0x1) << 7;
	$val |= ($flags['z'] & 0x7) << 4;
	$val |= ($flags['rcode'] & 0xf);

	return $val;
}

function decode_label($pkt, &$offset){
	$end_offset = null;
	$qname = '';

	while (1) {
		$len = ord($pkt[$offset]);
		$type = $len >> 6 & 0x2;

		if ($type) {
			switch ($type) {
				case 0x2:
					$new_offset = unpack('noffset', substr($pkt, $offset, 2));
					$end_offset = $offset + 2;
					$offset = $new_offset['offset'] & 0x3fff;
					break;
				case 0x1:
					break;
			}
			continue;
		}

		if ($len > (strlen($pkt) - $offset)) {
			return null;
		}

		if ($len == 0) {
			if ($qname == '') {
				$qname = '.';
			}
			++$offset;
			break;
		}
		$qname .= substr($pkt, $offset + 1, $len) . '.';
		$offset += $len + 1;
	}

	if (!is_null($end_offset)) {
		$offset = $end_offset;
	}

	return $qname;
}

function encode_label($str, $offset = null){
	if ($str === '.') {
		return "\0";
	}

	$res = '';
	$in_offset = 0;

	while (false !== $pos = strpos($str, '.', $in_offset)) {
		$res .= chr($pos - $in_offset) . substr($str, $in_offset, $pos - $in_offset);
		$offset += ($pos - $in_offset) + 1;
		$in_offset = $pos + 1;
	}

	return $res . "\0";
}

function decode_question($pkt, &$offset, $count){
	$res = array();

	for ($i = 0; $i < $count; ++$i) {
		if ($offset > strlen($pkt)) {
			return false;
		}
		$qname = decode_label($pkt, $offset);
		$tmp = unpack('nqtype/nqclass', substr($pkt, $offset, 4));
		$offset += 4;
		$tmp['qname'] = $qname;
		$res[] = $tmp;
	}
	return $res;
}

function encode_question($list, $offset){
	$res = '';

	foreach ($list as $rr) {
		$lbl = encode_label($rr['qname'], $offset);
		$offset += strlen($lbl) + 4;
		$res .= $lbl;
		$res .= pack('nn', $rr['qtype'], $rr['qclass']);
	}

	return $res;
}
