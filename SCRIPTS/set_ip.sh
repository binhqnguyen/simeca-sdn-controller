#!/bin/bash
source ../simeca_constants.sh

for i in enb2 enb3
do
	ssh -o StrictHostKeyChecking=no $i.$domain -t -t "cd /usr/local/src/simeca/SCRIPTS; sudo ./set_ip_enb.sh"
done

cd /usr/local/src/simeca/SCRIPTS
sudo ./set_ip_mme.sh

touch /tmp/SETIP
