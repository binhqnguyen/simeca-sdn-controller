#!/bin/bash
source ../simeca_constants.sh

if [ $(whoami) != "root" ]; then
		echo "This must be run as root"
		exit 1
fi


cd $EPC
sudo /opt/OpenEPC/bin/mm.kill.sh


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

sudo cp $XML/mm.xml /opt/OpenEPC/etc/
sudo cp $XML/mm_network.xml /opt/OpenEPC/etc/

net_c=$($START_SCRIPTS/get_interface_map.pl | grep an-lte | awk '{print $3}' )
sudo sed -i "s/net_c/$net_c/g" /opt/OpenEPC/etc/mm.xml
sudo sed -i "s/001011234567890/$imsi/g" /opt/OpenEPC/etc/mm.xml
sudo sed -i "s/Alice/$c_name/g" /opt/OpenEPC/etc/mm.xml


cd $SIMECA_EPC/wharf

screen -S mm -L -d -m -h 10000 /bin/bash -c "./wharf -f /opt/OpenEPC/etc/mm.xml"
screen -wipe


exit 0
