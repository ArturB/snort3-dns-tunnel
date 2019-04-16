#!/bin/bash

export SNORT_LUA_PATH=/usr/local/snort/etc/snort
export LUA_PATH=/usr/local/snort/include/snort/lua/\?.lua\;\;

for i in {enp0s8,enp0s9} ; do
	ip l set $i up
	ip l set $i mtu 3000
	ethtool -K $i tso off gro off
done

/usr/local/snort/bin/snort --daq afpacket -i enp0s8:enp0s9 -Q \
--tweaks inline -c /usr/local/snort/etc/snort/snort-custom.lua \
-s 65535 $@ 3> /root/snortlog/3log
