#!/bin/bash

###############MODIFY THIS FIRST!##################
UE_ID="304"
###################################################


NEXUS_IMSI="001011234560$UE_ID"
NEXUS_MISDN="491234567$UE_ID"
domain=$(hostname | awk -F'.' '{print $2"."$3"."$4"."$5}')
BIN_DIR="/opt/OpenEPC/bin"
HOME_DIR="$HOME"
#SIMECA_PATH="/usr/local/src/simeca"
#SIMECA_PATH="/opt/OpenEPC/bin/simeca"
SIMECA_PATH="/opt/simeca"  #EPC nodes scripts are in here
SCRIPTS="$SIMECA_PATH/script"
#SIMECA_SCRIPTS="/opt/OpenEPC/bin/simeca_scripts"
SIMECA_SCRIPTS="/opt/OpenEPC/bin/simeca_scripts"
MC_PATH="$SIMECA_PATH/simeca_controller"
CONF_PATH="$SIMECA_PATH/CONF"
#SIMECA_EPC="/proj/PhantomNet/binh/openepc-att-demo/" #Todo: package this
SIMECA_EPC="/opt/OpenEPC/" #Todo: package this
START_SCRIPTS="/opt/simeca/start_scripts"
START_SCRIPTS_OVS="/usr/local/src/simeca/start_scripts" #OVS start scripts
START_SCRIPTS_EPC="/opt/simeca/start_scripts" #EPC start scripts
HSS_PROVISION="$SIMECA_PATH/hss_provision"
EPC="$SIMECA_PATH/epc"
XML="$SIMECA_PATH/xml"
DATA="$HOME_DIR/data"
EPC_HOSTS="enb2 enb3 epc client1"
OVS_HOSTS="access1 access2 access3 tor hsw1 server1"
