#!/bin/bash

###############MODIFY THIS FIRST!##################
UE_ID="312" #UE13
###################################################


NEXUS_IMSI="001011234560$UE_ID"
NEXUS_MISDN="491234567$UE_ID"
domain=$(hostname | awk -F'.' '{print $2"."$3"."$4"."$5}')
SIMECA_PATH="/usr/local/src/simeca"
SCRIPTS="$SIMECA_PATH/script"
SIMECA_SCRIPTS="/usr/local/src/simeca_scripts"
MC_PATH="$SIMECA_PATH/simeca_controller"
CONF_PATH="$SIMECA_PATH/CONF"
SIMECA_EPC="/proj/PhantomNet/binh/openepc-att-demo/" #Todo: package this
START_SCRIPTS="$SIMECA_PATH/start_scripts"
HSS_PROVISION="$SIMECA_PATH/hss_provision"
EPC="$SIMECA_PATH/epc"
XML="$SIMECA_PATH/xml"
DATA="$SIMECA_PATH/data"
