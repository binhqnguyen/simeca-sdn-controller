#!/bin/bash
source ../simeca_constanst.sh

if [ $# -lt 1 ]; then
    echo "Usage <controller's ip, eg, 192.168.10.1>"
    exit 
fi


controller_ip=$1
sudo $START_SCRIPTS/run_ovs.sh || {
	echo "Can't run OVS. Exit!"
	exit 1
}


ovs-vsctl del-br br0

get_interface="perl $START_SCRIPTS/get_interface_map.pl"
interface_number=$($get_interface | grep -v mgmt | wc -l)
echo $interface_number
interfaces=()
for ((i=1; i <= $interface_number; i+=1))
do
    interface=$($get_interface | grep -v mgmt | head -$i | tail -1 | awk '{print $3}')
    interfaces+=($interface)
    echo add $i $interface
done

ovs-vsctl add-br br0 
ovs-vsctl set-fail-mode br0 secure
for i in "${interfaces[@]}"
do
    echo set ip $i
    ifconfig $i 0.0.0.0
    ovs-vsctl add-port br0 $i
done

ovs-vsctl set bridge br0 protocols=OpenFlow10,OpenFlow12,OpenFlow13

#GTP, GTP_ENCAP, GTP_DECAP
ovs-vsctl add-port br0 gtp1 -- set interface gtp1 type=gtp options:remote_ip=flow options:in_key=flow options:dst_port=2152
ovs-vsctl add-port br0 gtp2 -- set interface gtp2 type=gtp options:remote_ip=flow options:in_key=flow options:dst_port=2153
ovs-vsctl add-port br0 gtp3 -- set interface gtp3 type=gtp options:remote_ip=flow options:local_ip=flow options:in_key=flow options:out_key=flow options:dst_port=2154

ovs-vsctl set-controller br0 tcp:$controller_ip
ovs-vsctl show
