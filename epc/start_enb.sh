#!/bin/bash
source ../simeca_constants.sh

if [ $(whoami) != "root" ]; then
		echo "This must be run as root"
		exit 1
fi

cd $EPC
sudo /opt/OpenEPC/bin/enodeb.kill.sh


OFFSET_CELLID=4566
OFFSET_IP=29
OFFSET_MGN_IP=89
enb_name=$(hostname | cut -d"." -f1)
i=$((${#enb_name}-1))
enb=${enb_name:0:3}
enb_id=$(echo "${enb_name:$i:1}")
let cellid=$OFFSET_CELLID+$enb_id
let ip=$OFFSET_IP+$enb_id
let mgn_ip=$OFFSET_MGN_IP+$enb_id
an_lte_ip="192.168.3.$ip"
mgn="192.168.254.$mgn_ip"

sudo cp $XML/enodeb-ip-template.xml /opt/OpenEPC/etc/enodeb-ip.xml

net_c=$($START_SCRIPTS/get_interface_map.pl | grep an-lte | awk '{print $3}' )
if [ "$enb" == "enb" ]; then
    sudo ifconfig $net_c $an_lte_ip
fi
net_c_ip=$an_lte_ip
net_d=$($START_SCRIPTS/get_interface_map.pl | grep net-d | awk '{print $3}' )
net_d_ip=$($START_SCRIPTS/get_interface_map.pl | grep net-d | awk '{print $5}' )
sudo sed -i "s/NET_C_IP/$net_c_ip/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/NET_C/$net_c/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/NET_D_IP/$net_d_ip/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/NET_D/$net_d/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/CELLID/$cellid/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/eNodeB/$enb_name/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/MGN/$mgn/g" /opt/OpenEPC/etc/enodeb-ip.xml

sudo cp /opt/OpenEPC/etc/enodeb.xml /opt/OpenEPC/etc/enodeb.bk.xml
sudo cp /opt/OpenEPC/etc/enodeb-ip.xml /opt/OpenEPC/etc/enodeb.xml
cd $SIMECA_EPC/wharf_rel5

screen -S enodeb -L -d -m -h 10000 /bin/bash -c "./wharf -f /opt/OpenEPC/etc/enodeb.xml"
screen -wipe


exit 0
