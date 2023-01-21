#!/bin/bash
sudo launchctl unload -w /Library/LaunchDaemons/com.beefbad.phpDNS.plist
sudo launchctl remove -w /Library/LaunchDaemons/com.beefbad.phpDNS.plist
sudo rm -rfv /Library/LaunchDaemons/com.beefbad.phpDNS.plist
