#/bin/sh
source ../simeca_constants.sh


domain=$(hostname | awk -F'.' '{print $2"."$3"."$4"."$5}')

ssh -o StrictHostKeyChecking=no sgw.$domain -t -t "cd $EPC; sudo $EPC/start_mme.sh; echo mme.flush | nc -q 1 -u 192.168.254.80 10000" || {
        echo "Could not restart mme!"
        exit 1
}

echo mme.flush | nc -q 1 -u 192.168.254.80 10000

i=1
for e in enb2
do
    let enb_offset=90+$i
    ssh -o StrictHostKeyChecking=no $e.$domain -t -t "cd $EPC; sudo $EPC/start_enb.sh; echo enodeb.flush | nc -q 1 -u 192.168.254.$enb_offset 10000" || {
        echo "Could not restart $e!"
        exit 1
    }
    let i+=1
done

#Emualted client
ssh -o StrictHostKeyChecking=no client1.$domain -t -t "cd $EPC; sudo $EPC/start_mm.sh" || {
            echo "Could not restart mm client $client!"
            exit 1
}



#Restart OAI enodeb
#ssh -o StrictHostKeyChecking=no penb1.$domain "sudo $EPC/penb.kill.sh; /usr/local/src/airinterface/openairinterface5g/SCRIPTS/run_lte_soft_modem.sh" || {
#    echo "Could not restart OAI eNodeB!"
#    exit 1
#}

exit 0

