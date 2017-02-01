#!/bin/bash
source ../simeca_constants.sh

E_PATH="$HSS_PROVISION"
SQL="$E_PATH/load_clients.sql"
CLEAN_SQL="$E_PATH/clear_db.sql"
USER_DATA="$SIMECA_PATH/data/user.dat"

sudo mkdir -p $SIMECA_PATH/data
if [ $# -lt 2 ]; then
    echo "Usage: <Starting ID> <Number of IMSI entries>"
    exit 1
fi

mysql -u hss -pheslo hss_db_chess < $CLEAN_SQL ||  {
    echo "Error: Can't insert to database!"
    exit 1
}

python $HSS_PROVISION/generate_sql.py $1 $2 $SQL

mysql -u hss -pheslo hss_db_chess < $SQL ||  {
    echo "Error: Can't insert to database!"
    exit 1
}

#echo "" > $SCRIPTS/iot-controller-eval/user.dat
echo "" > $USER_DATA
for i in 1 2 3
do
    cut -d',' /tmp/IMSI_$i.data -f2 >> $USER_DATA
done

#python $SCRIPTS/iot-controller-eval/e2e_delay_exp/generate_p2p_path.py
#cp $SCRIPTS/iot-controller-eval/P2P.data $SCRIPTS/iot-controller/

echo "Done! inserted $2 IMSIs to database. Added IMSIs to the offload database $USER_DATA"
