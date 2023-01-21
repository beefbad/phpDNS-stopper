# phpDNS-stopper
A small script to stop DNS queries on macOS (Prevent verifing the signature via apple servers every time when applications launched). 
Now applications start instantly withot 

Install:

com.beefbad.phpDNS.plist:
	<key>WorkingDirectory</key>
	<string>/Users/apple/.phpDNS</string> <--- change path here
  ...
  <key>ProgramArguments</key>
	<array>
		<string>/Users/apple/.phpDNS/dnsfix.sh</string> <--- here
	</array>
------

dnsfix.sh:
if [ "$(ps ax | grep "php /Users/apple/.phpDNS/dnsfix.php" | grep -vc grep)" -lt 1 ]; then  <--- here
	php /Users/apple/.phpDNS/dnsfix.php <--- and here
------

set your DNS in default network adapter settings to 127.0.0.1 

and 

sudo sh install.sh

Uninstall:
sudo sh uninstall.sh

and remove DNS (127.0.0.1) from default network adapter settings
