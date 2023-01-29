#!/bin/bash
DIR=$(pwd);
LaunchDaemonPath="/Library/LaunchDaemons/com.beefbad.phpDNS.plist"

if [[ $EUID != 0 ]]; then
	echo "This program needs to run as root."
	exit 1
fi

echo -n -e "#!/bin/bash\nif [ \"\$(ps ax | grep \"php $DIR/phpDNSfix.php\" | grep -vc grep)\" -lt 1 ]; then\n\tphp $DIR/phpDNSfix.php\nelse\n\tprintf \"phpDNSfix.php is already running!\"\nfi\n">$DIR/phpDNSfix.sh
echo -n -e "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>com.beefbad.phpDNS</string>\n\t<key>KeepAlive</key>\n\t<true/>\n\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>WorkingDirectory</key>\n\t<string>/$DIR</string>\n\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>$DIR/phpDNSfix.sh</string>\n\t</array>\n\t<key>ThrottleInterval</key>\n\t<integer>1</integer>\n\t<key>Nice</key>\n\t<integer>1</integer>\n\t<key>UserName</key>\n\t<string>root</string>\n\t<key>StandardErrorPath</key>\n\t<string>$DIR/Logs/phpDNSstopper.log</string>\n\t<key>StandardOutPath</key>\n\t<string>$DIR/Logs/phpDNSstopper.log</string>\n</dict>\n</plist>">$LaunchDaemonPath
echo -n -e "#!/bin/bash\nsudo launchctl unload -w $LaunchDaemonPath\nsudo launchctl remove -w $LaunchDaemonPath\nsudo rm -rfv $LaunchDaemonPath">uninstall.sh

mkdir $DIR/Logs
chmod +w $DIR/Logs
#Non-root users should not edit these files during both run with root rights
sudo chown root:wheel $DIR/dphpDNSfix.php
sudo chown root:wheel $DIR/phpDNSfix.sh
sudo chmod +x $DIR/phpDNSfix.php
sudo chmod +x $DIR/phpDNSfix.sh
sudo chown root:wheel $LaunchDaemonPath
sudo launchctl load -w /$LaunchDaemonPath
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
			break
		fi
	fi
done <<< "$(networksetup -listnetworkserviceorder | grep 'Hardware Port')"
if [ -z "$currentservice" ]; then
	>&2 echo "Could not find current network!"
	exit 1
fi