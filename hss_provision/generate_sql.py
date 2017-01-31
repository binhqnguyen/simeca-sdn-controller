import random
import subprocess 
from subprocess import call
import os
import sys

START_IMSI=1234567890
NUM_ENB=3
CLOUD_SERVER_LIST=['192.168.7.10']
NUM_OF_CLIENT_SERVER=100 #how many servers are clients

def generate_sql(starting_id, number_of_entries, sql_file_name):
    output = open(sql_file_name, "w")
    imsi_file_1 = open("/tmp/IMSI_1.data","w")
    imsi_file_2 = open("/tmp/IMSI_2.data","w")
    imsi_file_3 = open("/tmp/IMSI_3.data","w")
    imsi_server_file_1 = open("/tmp/SERVER_IMSI_1.data","w")
    imsi_server_file_2 = open("/tmp/SERVER_IMSI_2.data","w")
    imsi_server_file_3 = open("/tmp/SERVER_IMSI_3.data","w")

    #imsi_file.write("starting_id=%d, #_of_entries=%d, sql_file=%s\n"%(starting_id, number_of_entries, sql_file_name))
    ID = starting_id;
    imsi_list = {}
    imsi_file = imsi_file_1
    imsi_server_file = imsi_server_file_1
    cnt = 0
    group = 0
    ue_per_enb = number_of_entries/NUM_ENB
    for i in range(0,number_of_entries):
        if cnt==ue_per_enb:
            group += 1
            cnt = 0
        if group == 1:
            imsi_file = imsi_file_2
            imsi_server_file = imsi_server_file_2
        if group == 2:
            imsi_server_file = imsi_server_file_3
            imsi_file = imsi_file_3
        ID += 1;
        #imsi = "00101%d"%random.randint(1000000000,9999999999)
        imsi = "00101%d"%(START_IMSI+i)
        #while (imsi in imsi_list):
        #    imsi = "00101%d"%random.randint(1000000000,9999999999)
        imsi_list[imsi] = 1
        #imsi = "001011234567899"
        server_index=random.randint(0,len(CLOUD_SERVER_LIST)-1)
        imsi_file.write(str(ID)+","+imsi+","+CLOUD_SERVER_LIST[server_index]+"\n")
        
        is_server_p = random.randint(0,ue_per_enb)
        if is_server_p < NUM_OF_CLIENT_SERVER/NUM_ENB:
            imsi_server_file.write(str(ID)+","+imsi+"\n")

        cnt+=1
        output.write("/* ---------%s--------- */\n"%imsi)
        output.write("insert into imsu set id=%s, name='auto%s', id_capabilities_set=1;\n\n"%(ID,imsi))

        output.write("insert into imsi set id=%s, id_imsu=%s, identity='%s',\n\
            odb_barring=0, mme_address='', mme_realm='', sgsn_address='',\n\
            sgsn_realm='', msc_address='', msc_realm='', apn_oi_replacement='',\n\
            id_qos_profile_default=1, ics_indicator=1, network_access_mode=2,\n\
            id_apn_configuration_profile=1, amf=0x8000,op='\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0', non_3gpp_status=0;\n\n"%(ID, ID,imsi))

        output.write("insert into imsi_allowed_apn set id_imsi=%s, id_apn_configuration_profile=1,priority=10;\n\n"%(ID))

        output.write("insert into imsi_apn set id_imsi=%s, id_apn_configuration_profile=1,\n\
            id_apn_configuration=4, ipv4='', ipv6='',\n\
            pgw_identity='pgw.epc.mnc001.mcc001.3gppnetwork.org',\n\
            pgw_realm='epc.mnc001.mcc001.3gppnetwork.org',\n\
            pgw_ipv4='192.168.1.10', pgw_ipv6='fc00:1234:1::10', is_static_pgw=1;\n\n"%ID)

        output.write("insert into imsi_visited_network set id_imsi=%s, id_visited_network=1;\n\n"%ID)
    print "Done generating %d IMSI, sql file is %s, IMSI file is IMSI_1/2/3.data" % (number_of_entries, sql_file_name)
    #returnval = execute_cmd("./load_clients.sh %s"%sql_file_name)
    #returnval = call(["./load_clients.sh %s"%sql_file_name], shell=True)
    #if (returnval>=0):
    #    print "Done adding %d imsis to the hss database. Sql file is %s" % (number_of_entries, sql_file_name)
    #else:
    #    print "Error! Can't add imsis to hss database, sql file is %s" % sql_file_name

#labels = []
#values = []

#labels,values,types = read_file("imsu.data")
#create_sql_line("imsu", labels, values, types, "imsu.sql")
if __name__ == "__main__":
    if (len(sys.argv) != 4):
        print "Usage: <starting ID, eg, 100> <number of IMSI entries> <sql file name, eg, load_clients.sql>"
        sys.exit(1) 
    else:
        generate_sql(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3])
        sys.exit(0)




