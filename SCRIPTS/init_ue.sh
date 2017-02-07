#!/bin/bash
source ../simeca_constants.sh

if [ $# -lt 1 ]; then
	echo "Usage: <UE_ID, eg, 310>"
	exit 1
fi

UE_ID=$1

sudo sed -i "s/UE_ID=.*/UE_ID=\"$UE_ID\"/g" $SIMECA_PATH/simeca_constants.sh || {
	echo "Can't modify UE_ID! Should retry!!!"
	exit 1
}

sudo touch /var/log/UE_INITED

exit 0
