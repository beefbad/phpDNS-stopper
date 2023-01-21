#!/bin/bash
if [ "$(ps ax | grep "php /Users/apple/.phpDNS/dnsfix.php" | grep -vc grep)" -lt 1 ]; then
	php /Users/apple/.phpDNS/dnsfix.php
else
	printf "phpDNS is already running!\n"
fi