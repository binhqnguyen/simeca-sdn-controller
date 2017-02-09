#!/bin/bash
source /opt/simeca/simeca_constants.sh

if [ $(whoami) != "root" ]; then
		echo "This must be run as root"
		exit 1
fi

cd $EPC
sudo /opt/OpenEPC/bin/mme.kill.sh

#sudo cp $XML/mme.xml /opt/OpenEPC/etc/

cd $SIMECA_EPC/wharf

screen -S mme -L -d -m -h 10000 /bin/bash -c "./wharf -f /opt/OpenEPC/etc/mme.xml"
screen -wipe

exit 0
