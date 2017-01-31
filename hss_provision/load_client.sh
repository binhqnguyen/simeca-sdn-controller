#!/bin/sh

if [ $# -lt 4 ]; then
    echo "Usage: <IMSI, eg, 001011234567899> <MSISDN, eg,491234567899> <ID, eg, 12> <SQN number>"
    exit 1
fi

IMSI=$1
MSISDN=$2
ID=$3
sqn=$4

SQL_FILE=ue$IMSI-tmp.sql
echo "/*-------HSS database generated for IMSI $IMSI, MSISDN $MSISDN, ID $ID------*/" > $SQL_FILE

echo "delete from imsu where id=$ID;" >> $SQL_FILE
echo "delete from imsi where id=$ID;" >> $SQL_FILE
echo "delete from imsi_allowed_apn where id_imsi=$ID;" >> $SQL_FILE
echo "delete from imsi_apn where id_imsi=$ID;" >> $SQL_FILE
echo "delete from imsi_msisdn where id=$ID;" >> $SQL_FILE
echo "delete from imsi_visited_network where id_imsi=$ID;" >> $SQL_FILE
echo "delete from impu_visited_network where id=$ID;" >> $SQL_FILE
echo "delete from impi where id=$ID;" >> $SQL_FILE
echo "delete from impu where id=$ID;" >> $SQL_FILE
echo "delete from msisdn where id=$ID;" >> $SQL_FILE

echo "" >> $SQL_FILE
echo "insert into imsu set id=$ID, name='auto$IMSI', id_capabilities_set=1, id_preferred_scscf_set=1;" >> $SQL_FILE

echo "" >> $SQL_FILE
echo "insert into impu_visited_network set id=$ID, id_impu=$ID, id_visited_network=1;" >> $SQL_FILE

echo "" >> $SQL_FILE
echo "insert into imsi set id=$ID, id_imsu=$ID, identity='$IMSI',
            odb_barring=0, mme_address='', mme_realm='', sgsn_address='', 
            sgsn_realm='', msc_address='', msc_realm='', apn_oi_replacement='', 
            id_qos_profile_default=2, ics_indicator=1, network_access_mode=2, 
            id_apn_configuration_profile=1,k=0x00112233445566778899aabbccddeeff,amf=0x8000,
            op=0x01020304050607080910111213141516,sqn=$sqn,non_3gpp_status=0;" >> $SQL_FILE

#            /*   op=0x01020304050607080910111213141516, sqn='000000002368',non_3gpp_status=0;" >> $SQL_FILE*/

echo "" >> $SQL_FILE
echo "insert into imsi_allowed_apn set id=$ID, id_imsi=$ID, id_apn_configuration_profile=1,priority=10;" >> $SQL_FILE

echo "" >> $SQL_FILE
echo "insert into imsi_apn set id_imsi=$ID, id_apn_configuration_profile=1,
            id_apn_configuration=4, ipv4='', ipv6='',
            pgw_identity='pgw.epc.mnc001.mcc001.3gppnetwork.org',
            pgw_realm='epc.mnc001.mcc001.3gppnetwork.org',
            pgw_ipv4='192.168.1.10', pgw_ipv6='fc00:1234:1::10', is_static_pgw=1;" >> $SQL_FILE

echo "" >> $SQL_FILE
echo "insert into imsi_msisdn set id=$ID, id_imsi=$ID,id_msisdn=$ID;" >> $SQL_FILE

echo "insert into imsi_visited_network set id_imsi=$ID, id_visited_network=1;" >> $SQL_FILE

echo "" >> $SQL_FILE
echo "insert into impi set id=$ID, id_imsu=$ID, identity='auto$IMSI@openepc.test',auth_scheme=71,
            default_auth_scheme=1, k=0x00112233445566778899aabbccddeeff, amf=0x0000,
            op=0x01020304050607080910111213141516, zh_uicc_type=0,
            zh_key_life_time=3600, zh_default_auth_scheme=1;" >> $SQL_FILE

#            op=0x01020304050607080910111213141516, sqn='000000000021', zh_uicc_type=0,

echo "" >> $SQL_FILE
echo "insert into impu set id=$ID, identity='sip:auto00101234567899@openepc.test',type=0,
    barring=0, user_state=0, id_sp=0, id_implicit_set=1, id_charging_info=6, 
    psi_activation=0, can_register=1;" >> $SQL_FILE

echo "" >> $SQL_FILE
echo "insert into msisdn set id=$ID,identity=$MSISDN;" >> $SQL_FILE


echo "Generated HSS database entries for IMSI $IMSI, output is $SQL_FILE"

echo "Loading HSS database ... "
mysql -u hss -pheslo hss_db_chess < $SQL_FILE ||  {
    echo "[Error:] Can't insert to database!"
    exit 1
}

rm $SQL_FILE
echo "Successfully insert HSS databse for IMSI $IMSI!"