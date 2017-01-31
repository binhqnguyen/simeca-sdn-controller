#/bin/bash
source ../simeca_constants.sh


if [ $# -lt 2 ]; then
    echo "Usage <ACCESS switches list, eg, access1,access2> <Other OVS switches, eg, tor,hsw1,hsw2>"
    exit 1
fi

sudo pip install networkx

IFS=',' read -a access_switch_list <<< "$1"
IFS=',' read -a intermediary_switch_list <<< "$2"

controller_ip=$($START_SCRIPTS/get_interface_map.pl | grep mgmt | awk '{print $5}')
mgmt_inf=$($START_SCRIPTS/get_interface_map.pl | grep mgmt | awk '{print $3}')
domain=$(hostname | awk -F'.' '{print $2"."$3"."$4"."$5}')

subnet=$(echo $controller_ip | awk -F'.' '{print $1"."$2"."$3".0/24"}')
echo "mgmt = $mgmt_inf, controller_ip = $controller_ip, subnet = $subnet"
sudo ip addr add dev $mgmt_inf $controller_ip
sudo ip route add $subnet dev $mgmt_inf 
sudo apt-get install tshark

for a in "${access_switch_list[@]}"
do
    echo "Starting switch $a.$domain, Controller IP = $controller_ip"
    ssh $a.$domain "cd $START_SCRIPTS && sudo ./start_access_switch_with_controller.sh $controller_ip" || {
        echo "Could not start Access switch $a!"
        exit 1
    }
done

for s in "${intermediary_switch_list[@]}"
do
    echo "Starting switch $s.$domain, Controller IP = $controller_ip"
    ssh $s.$domain "cd $START_SCRIPTS && sudo ./start_intermediary_switch_with_controller.sh $controller_ip" || {
        echo "Could not start Intermediary switch $s!"
        exit 1
    }
done

