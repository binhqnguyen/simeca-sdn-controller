#!/bin/sh

source ../simeca_constants.sh
#
#Start components for ATT-demo.
#Run this on MF (MME) node.
#
echo "==========Starting OVS switches .... ==========="
cd $START_SCRIPTS
bash $START_SCRIPTS/start_switches.sh access1,access2,access3 tor,hsw1

echo "==========Adding IMSIs to HSS database .... ============"
ssh -o StrictHostKeyChecking=no epc.$domain -t -t "cd $HSS_PROVISION && sudo ./load_clients.sh 1 3"
ssh -o StrictHostKeyChecking=no epc.$domain -t -t "cd $HSS_PROVISION && sudo ./load_1_client.sh 001011234567899 491234567899 100"
ssh -o StrictHostKeyChecking=no epc.$domain -t -t "cd $HSS_PROVISION && sudo ./load_1_client.sh $NEXUS_IMSI $NEXUS_MISDN 200"

sudo bash -c 'echo "001011234567890|$NEXUS_IMSI" > $CONF_PATH/P2P_ATTACH.data' #for P2P HO
sudo bash -c 'echo "1,001011234567899,192.168.7.10" > $CONF_PATH/SERVER.data'
sudo bash -c 'echo "2,001011234567890,192.168.7.10" >> $CONF_PATH/SERVER.data'
sudo bash -c 'echo "3,001011234567891,192.168.7.10" >> $CONF_PATH/SERVER.data'
sudo bash -c 'echo "4,$NEXUS_IMSI,192.168.7.10" >> $CONF_PATH/SERVER.data'


echo "==========Starting eNBs and MF .... ============"
cd $EPC
bash $EPC/restart_epc.sh

echo "==========Copying IMSI data into $DATA ==========="
scp -o StrictHostKeyChecking=no 'epc.$domain:/tmp/IMSI_*' /tmp/
sudo cp /tmp/IMSI_* $DATA/

echo "==========Starting MC .... ============"
cd $MC_PATH
sudo pip install MySQL-python
ryu-manager MC.py
