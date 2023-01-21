#!/bin/bash
chmod +x dnsfix.php
chmod +x dnsfix.sh
sudo cp -R com.beefbad.phpDNS.plist /Library/LaunchDaemons/com.beefbad.phpDNS.plist
sudo chown root:wheel /Library/LaunchDaemons/com.beefbad.phpDNS.plist
sudo launchctl load -w /Library/LaunchDaemons/com.beefbad.phpDNS.plist
