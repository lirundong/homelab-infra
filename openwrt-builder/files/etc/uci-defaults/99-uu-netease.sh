#!/bin/sh

/usr/bin/curl -sSL http://uu.gdl.netease.com/uuplugin-script/202012111056/install.sh -o /tmp/install.sh
sh /tmp/install.sh openwrt $(uname -m)
rm /tmp/install.sh
