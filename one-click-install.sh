#!/bin/bash
DIR=$(pwd);
LaunchDaemonPath="/Library/LaunchDaemons/com.beefbad.phpDNS.plist"

if [[ $EUID != 0 ]]; then
	echo "This program needs to run as root."
	exit 1
fi
echo -n -e "#!/bin/bash\nif [ \"\$(ps ax | grep \"php $DIR/phpDNSfix.php\" | grep -vc grep)\" -lt 1 ]; then\n\tphp $DIR/phpDNSfix.php\nelse\n\tprintf \"phpDNSfix.php is already running!\"\nfi\n">$DIR/phpDNSfix.sh
echo -n -e "<?php\ndefine('BIND_IP', '127.0.0.1');\ndefine('BIND_PORT', 53);\ndefine('QUERY_TYPES', [\n\t1 => 'A',\n\t2 => 'NS',\n\t5 => 'CNAME',\n\t6 => 'SOA',\n\t12 => 'PTR',\n\t15 => 'MX',\n\t16 => 'TXT',\n\t28 => 'AAAA',\n\t41 => 'OPT',\n\t252 => 'AXFR',\n\t255 => 'ANY',\n\t18 => 'AFSDB',\n\t42 => 'APL',\n\t257 => 'CAA',\n\t60 => 'CDNSKEY',\n\t59 => 'CDS',\n\t37 => 'CERT',\n\t49 => 'DHCID',\n\t32769 => 'DLV',\n\t48 => 'DNSKEY',\n\t43 => 'DS',\n\t45 => 'IPSECKEY',\n\t25 => 'KEY',\n\t36 => 'KX',\n\t29 => 'LOC',\n\t35 => 'NAPTR',\n\t47 => 'NSEC',\n\t50 => 'NSEC3',\n\t51 => 'NSEC3PARAM',\n\t46 => 'RRSIG',\n\t17 => 'RP',\n\t24 => 'SIG',\n\t33 => 'SRV',\n\t44 => 'SSHFP',\n\t32768 => 'TA',\n\t249 => 'TKEY',\n\t52 => 'TLSA',\n\t250 => 'TSIG',\n\t256 => 'URI',\n\t39 => 'DNAME',\n]);\n\$socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);\n\nif (!\$socket) {\n\tprintf('Cannot create socket (socket error: %s).', socket_strerror(socket_last_error(\$socket)));\n\texit;\n}\n\nif (!socket_bind(\$socket, BIND_IP, BIND_PORT)) {\n\tprintf('Cannot bind socket to %s:%d (socket error: %s).', BIND_IP, BIND_PORT, socket_strerror(socket_last_error(\$socket)));\n\texit;\n}\n\nwhile (true) {\n\t\$buffer = \$ip = \$port = null;\n\n\tif (!socket_recvfrom(\$socket, \$buffer, 512, null, \$ip, \$port)) {\n\t\tprintf('Cannot read from socket ip: %s, port: %d (socket error: %s).', \$ip, \$port, socket_strerror(socket_last_error(\$socket)));\n\t} else {\n\t\t\$response = handle_query(\$buffer, \$question);\n\t\t//PRINT\n\t\tforeach(\$question as \$query){\n\t\t\tprintf(\"[%s] %s\n\", QUERY_TYPES[\$query['qtype']], \$query['qname']);\n\t\t}\n\t\t//END PRINT\n\t\tif (!socket_sendto(\$socket, \$response, strlen(\$response), 0, \$ip, \$port)) {\n\t\t\tprintf('Cannot send reponse to socket ip: %s, port: %d (socket error: %s).', \$ip, \$port, socket_strerror(socket_last_error(\$socket)));\n\t\t}\n\t}\n}\necho \"Done\n\";\n\nfunction handle_query(\$buffer, &\$question){\n\t\$data = unpack('npacket_id/nflags/nqdcount/nancount/nnscount/narcount', \$buffer);\n\t\$flags = decode_flags(\$data['flags']);\n\t\$offset = 12;\n\n\t\$question = decode_question(\$buffer, \$offset, \$data['qdcount']);\n\n\t\$flags['rcode'] = 3;\n\t\$flags['qr'] = 1;\n\t\$flags['ra'] = 0;\n\n\t\$qdcount = count(\$question);\n\n\t\$response = pack('nnnnnn', \$data['packet_id'], encode_flags(\$flags), \$qdcount, 0, 0, 0);\n\t\$response .= encode_question(\$question, strlen(\$response));\n\n\treturn \$response;\n}\n\nfunction decode_flags(\$flags){\n\treturn [\n\t\t'qr'\t => \$flags >> 15 & 0x1,\n\t\t'opcode' => \$flags >> 11 & 0xf,\n\t\t'aa'\t => \$flags >> 10 & 0x1,\n\t\t'tc'\t => \$flags >> 9 & 0x1,\n\t\t'rd'\t => \$flags >> 8 & 0x1,\n\t\t'ra'\t => \$flags >> 7 & 0x1,\n\t\t'z'\t\t => \$flags >> 4 & 0x7,\n\t\t'rcode'\t => \$flags & 0xf,\n\t];\n}\n\nfunction encode_flags(\$flags){\n\t\$val = 0;\n\n\t\$val |= (\$flags['qr'] & 0x1) << 15;\n\t\$val |= (\$flags['opcode'] & 0xf) << 11;\n\t\$val |= (\$flags['aa'] & 0x1) << 10;\n\t\$val |= (\$flags['tc'] & 0x1) << 9;\n\t\$val |= (\$flags['rd'] & 0x1) << 8;\n\t\$val |= (\$flags['ra'] & 0x1) << 7;\n\t\$val |= (\$flags['z'] & 0x7) << 4;\n\t\$val |= (\$flags['rcode'] & 0xf);\n\n\treturn \$val;\n}\n\nfunction decode_label(\$pkt, &\$offset){\n\t\$end_offset = null;\n\t\$qname = '';\n\n\twhile (1) {\n\t\t\$len = ord(\$pkt[\$offset]);\n\t\t\$type = \$len >> 6 & 0x2;\n\n\t\tif (\$type) {\n\t\t\tswitch (\$type) {\n\t\t\t\tcase 0x2:\n\t\t\t\t\t\$new_offset = unpack('noffset', substr(\$pkt, \$offset, 2));\n\t\t\t\t\t\$end_offset = \$offset + 2;\n\t\t\t\t\t\$offset = \$new_offset['offset'] & 0x3fff;\n\t\t\t\t\tbreak;\n\t\t\t\tcase 0x1:\n\t\t\t\t\tbreak;\n\t\t\t}\n\t\t\tcontinue;\n\t\t}\n\n\t\tif (\$len > (strlen(\$pkt) - \$offset)) {\n\t\t\treturn null;\n\t\t}\n\n\t\tif (\$len == 0) {\n\t\t\tif (\$qname == '') {\n\t\t\t\t\$qname = '.';\n\t\t\t}\n\t\t\t++\$offset;\n\t\t\tbreak;\n\t\t}\n\t\t\$qname .= substr(\$pkt, \$offset + 1, \$len) . '.';\n\t\t\$offset += \$len + 1;\n\t}\n\n\tif (!is_null(\$end_offset)) {\n\t\t\$offset = \$end_offset;\n\t}\n\n\treturn \$qname;\n}\n\nfunction encode_label(\$str, \$offset = null){\n\tif (\$str === '.') {\n\t\treturn \"\0\";\n\t}\n\n\t\$res = '';\n\t\$in_offset = 0;\n\n\twhile (false !== \$pos = strpos(\$str, '.', \$in_offset)) {\n\t\t\$res .= chr(\$pos - \$in_offset) . substr(\$str, \$in_offset, \$pos - \$in_offset);\n\t\t\$offset += (\$pos - \$in_offset) + 1;\n\t\t\$in_offset = \$pos + 1;\n\t}\n\n\treturn \$res . \"\0\";\n}\n\nfunction decode_question(\$pkt, &\$offset, \$count){\n\t\$res = array();\n\n\tfor (\$i = 0; \$i < \$count; ++\$i) {\n\t\tif (\$offset > strlen(\$pkt)) {\n\t\t\treturn false;\n\t\t}\n\t\t\$qname = decode_label(\$pkt, \$offset);\n\t\t\$tmp = unpack('nqtype/nqclass', substr(\$pkt, \$offset, 4));\n\t\t\$offset += 4;\n\t\t\$tmp['qname'] = \$qname;\n\t\t\$res[] = \$tmp;\n\t}\n\treturn \$res;\n}\n\nfunction encode_question(\$list, \$offset){\n\t\$res = '';\n\n\tforeach (\$list as \$rr) {\n\t\t\$lbl = encode_label(\$rr['qname'], \$offset);\n\t\t\$offset += strlen(\$lbl) + 4;\n\t\t\$res .= \$lbl;\n\t\t\$res .= pack('nn', \$rr['qtype'], \$rr['qclass']);\n\t}\n\n\treturn \$res;\n}\n">$DIR/phpDNSfix.php
echo -n -e "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>com.beefbad.phpDNS</string>\n\t<key>KeepAlive</key>\n\t<true/>\n\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>WorkingDirectory</key>\n\t<string>/$DIR</string>\n\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>$DIR/phpDNSfix.sh</string>\n\t</array>\n\t<key>ThrottleInterval</key>\n\t<integer>1</integer>\n\t<key>Nice</key>\n\t<integer>1</integer>\n\t<key>UserName</key>\n\t<string>root</string>\n\t<key>StandardErrorPath</key>\n\t<string>$DIR/Logs/phpDNSstopper.log</string>\n\t<key>StandardOutPath</key>\n\t<string>$DIR/Logs/phpDNSstopper.log</string>\n</dict>\n</plist>">$LaunchDaemonPath
echo -n -e "#!/bin/bash\nsudo launchctl unload -w /Library/LaunchDaemons/com.beefbad.phpDNS.plist\nsudo launchctl remove -w /Library/LaunchDaemons/com.beefbad.phpDNS.plist\nsudo rm -rfv /Library/LaunchDaemons/com.beefbad.phpDNS.plist">uninstall.sh

mkdir $DIR/Logs
chmod +w $DIR/Logs
#Non-root users should not edit these files during both run with root rights
sudo chown root:wheel $DIR/dphpDNSfix.php
sudo chown root:wheel $DIR/phpDNSfix.sh
sudo chmod +x $DIR/phpDNSfix.php
sudo chmod +x $DIR/phpDNSfix.sh
sudo chown root:wheel /Library/LaunchDaemons/com.beefbad.phpDNS.plist
sudo launchctl load -w /Library/LaunchDaemons/com.beefbad.phpDNS.plist
while read -r line; do
	sname=$(echo "$line" | awk -F  "(, )|(: )|[)]" '{print $2}')
	sdev=$(echo "$line" | awk -F  "(, )|(: )|[)]" '{print $4}')
	if [ -n "$sdev" ]; then
		ifout="$(ifconfig "$sdev" 2>/dev/null)"
		echo "$ifout" | grep 'status: active' > /dev/null 2>&1
		rc="$?"
		if [ "$rc" -eq 0 ]; then
			currentservice="$sname"
			sudo networksetup -setdnsservers $currentservice 127.0.0.1
			sudo dscacheutil -flushcache
			sudo killall -HUP mDNSResponder
			break;
		fi
	fi
done <<< "$(networksetup -listnetworkserviceorder | grep 'Hardware Port')"
if [ -z "$currentservice" ]; then
	>&2 echo "Could not find current network!"
	exit 1
fi