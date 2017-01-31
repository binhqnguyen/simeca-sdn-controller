#!/bin/bash
source ../simeca_constants.sh

if [ $(whoami) != "root" ]; then
		echo "This must be run as root"
		exit 1
fi

if [ $# -lt 2 ]; then
		echo "Usage: <service to start, eg, mme> <xml file path, eg, /opt/OpenEPC/etc/mme.xml>"
		exit 1;
fi

cd $EPC
sudo $EPC/kill.sh
sudo /opt/OpenEPC/bin/$1.kill.sh


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

imsi="001011234567890"
client_name=$(hostname | cut -d"." -f1)
case $client_name in
    alice)
        imsi="001011234567890"
        c_name="Alice"
        ;;
    bob)
        imsi="001011234567891"
        c_name="Bob"
        ;;
    charlie)
        imsi="001011234567892"
        c_name="Charlie"
        ;;

    *)
        echo "Client name unknown!"
        ;;
esac

sudo cp $SIMECA_PATH/enodeb-ip-template.xml /opt/OpenEPC/etc/enodeb-ip.xml
sudo cp $SIMECA_PATH/mme.xml /opt/OpenEPC/etc/
sudo cp $SIMECA_PATH/mm.xml /opt/OpenEPC/etc/
sudo cp $SIMECA_PATH/mm_network.xml /opt/OpenEPC/etc/

net_c=$($SIMECA_PATH/get_interface_map.pl | grep an-lte | awk '{print $3}' )
if [ "$enb" == "enb" ]; then
    sudo ifconfig $net_c $an_lte_ip
fi
#net_c_ip=$(/proj/PhantomNet/binh/openepc/code/script/iot-controller-no-tunel/get_interface_map.pl | grep an-lte | awk '{print $5}' )
net_c_ip=$an_lte_ip
net_d=$($SIMECA_PATH/get_interface_map.pl | grep net-d | awk '{print $3}' )
net_d_ip=$($SIMECA_PATH/get_interface_map.pl | grep net-d | awk '{print $5}' )
sudo sed -i "s/NET_C_IP/$net_c_ip/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/NET_C/$net_c/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/NET_D_IP/$net_d_ip/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/NET_D/$net_d/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/CELLID/$cellid/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/eNodeB/$enb_name/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/MGN/$mgn/g" /opt/OpenEPC/etc/enodeb-ip.xml
sudo sed -i "s/net_c/$net_c/g" /opt/OpenEPC/etc/mm.xml
sudo sed -i "s/001011234567890/$imsi/g" /opt/OpenEPC/etc/mm.xml
sudo sed -i "s/Alice/$c_name/g" /opt/OpenEPC/etc/mm.xml


cd $SIMECA_EPC/wharf_rel5

screen -S $1 -L -d -m -h 10000 /bin/bash -c "./wharf -f $2"
screen -wipe


exit 0
