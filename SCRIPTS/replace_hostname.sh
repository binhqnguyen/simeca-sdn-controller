#!/bin/bash

source ../simeca_constants.sh
#domain=$(hostname | awk '{print $2"."$3"."$4"."$5}')

#for i in $OVS_HOSTS
#do
#	echo "Replacing hostname of host $i"
#	ssh -o StrictHostKeyChecking=no $i.$domain "/usr/local/src/simeca/SCRIPTS/replace_host_local.sh"
#done

for i in $EPC_HOSTS
do
	echo "Replacing hostname of host $i"
	ssh -o StrictHostKeyChecking=no $i.$domain -t -t "cd $BIN_DIR; sudo ./replace_host_local.sh"
done


touch /tmp/HOST_REPLACED
