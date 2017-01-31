#!/bin/bash
source ../simeca_constants.sh

#
#Start components for ATT-demo.
#Run this on MF (MME) node.
#


echo "==========Starting eNBs and MF .... ============"
cd $SIMECA_PATH
bash $SIMECA_PATH/restart_epc.sh

echo "==========Starting MC .... ============"
cd $MC_PATH
ps ax | grep MC | awk '{system("sudo kill "$1)}'
ryu-manager MC.py
