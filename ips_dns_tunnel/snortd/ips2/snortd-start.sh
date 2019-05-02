#!/bin/bash

ip l set ens33 up
ip l set ens37 up
ip l set ens33 mtu 4000
ip l set ens37 mtu 4000
ethtool -K ens33 tso off gro off
ethtool -K ens37 tso off gro off

snort --daq afpacket -i "ens33:ens37" \
      -Q --tweaks inline -s 65535 $@ & \
      --plugin-path /usr/local/snort/lib64/snort_extra \ 
      -A alert_full \
      -R ~/myriles.rules
