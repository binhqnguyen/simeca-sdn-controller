#!/bin/bash
source /opt/simeca/simeca_constants.sh

controller_ip=$($START_SCRIPTS_EPC/get_interface_map.pl | grep mgmt | awk '{print $5}')
mgmt_inf=$($START_SCRIPTS_EPC/get_interface_map.pl | grep mgmt | awk '{print $3}')

subnet=$(echo $controller_ip | awk -F'.' '{print $1"."$2"."$3".0/24"}')
#echo "mgmt = $mgmt_inf, controller_ip = $controller_ip, subnet = $subnet"
sudo ip addr add dev $mgmt_inf $controller_ip
sudo ip route add $subnet dev $mgmt_inf 

echo "controller $controller_ip"
exit 0
