#!/bin/bash

source ../simeca_constants.sh


if [ ! -f /tmp/UE_INITED ]; then
	echo "The UE_ID does not seem to be initialized. Did you forget to run ./init_ue.sh?"
	exit 1
fi

#Replace hostname
if [ ! -f /tmp/HOST_REPLACED ]; then
	./replace_hostname.sh
fi


#Clean up ip route
if [ ! -f /tmp/SETIP ]; then
	./set_ip.sh
fi



#
#Start components for ATT-demo.
#Run this on MF (MME) node.
#
echo "==========Starting OVS switches .... ==========="
cd $START_SCRIPTS_EPC
bash $START_SCRIPTS_EPC/start_switches.sh access1,access2,access3 tor,hsw1

echo "==========Adding IMSIs to HSS database .... ============"
ssh -o StrictHostKeyChecking=no epc.$domain  "cd $HSS_PROVISION && ./load_clients.sh 1 3"
ssh -o StrictHostKeyChecking=no epc.$domain  "cd $HSS_PROVISION && ./load_1_client.sh 001011234567899 491234567899 100"
ssh -o StrictHostKeyChecking=no epc.$domain  "cd $HSS_PROVISION && ./load_1_client.sh $NEXUS_IMSI $NEXUS_MISDN 200"

echo $CONF_PATH/P2P_ATTACH.data

echo "001011234567890|$NEXUS_IMSI" > /tmp/P2P_ATTACH.data #for P2P HO
echo "1,001011234567899,192.168.7.10" > /tmp/SERVER.data
echo "2,001011234567890,192.168.7.10" >> /tmp/SERVER.data
echo "3,001011234567891,192.168.7.10" >> /tmp/SERVER.data
echo "4,$NEXUS_IMSI,192.168.7.10" >> /tmp/SERVER.data


mkdir -p $DATA
cp /tmp/P2P_ATTACH.data  $HOME_DIR/data/P2P_ATTACH.data #for P2P HO
cp /tmp/SERVER.data  $HOME_DIR/data/SERVER.data


echo "==========Starting eNBs and MF .... ============"
cd $EPC
bash $EPC/restart_epc.sh

echo "==========Copying IMSI data into $DATA ==========="
scp -o StrictHostKeyChecking=no "epc.$domain:/tmp/IMSI_*" /tmp/
cp /tmp/IMSI_* $DATA/

echo "==========Starting MC .... ============"
cd $MC_PATH
#sudo pip install MySQL-python
mkdir /tmp/xml
ryu-manager MC.py
