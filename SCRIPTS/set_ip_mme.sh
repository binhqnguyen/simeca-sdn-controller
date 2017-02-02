#!/bin/bash

sudo ip route | grep -v "default\|155\|eth0" | awk '{system("sudo ip route del " $1)}'

mgmt=$(/usr/local/src/simeca/start_scripts/get_interface_map.pl | grep "mgmt" | awk '{print $3}')
netd=$(/usr/local/src/simeca/start_scripts/get_interface_map.pl | grep "net-d" | awk '{print $3}')


sudo ip route add 192.168.4.0/24 dev $netd
sudo ip route add 192.168.254.0/24 dev $mgmt

