#Copyright Binh Nguyen University of Utah (binh@cs.utah.edu)
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

#!/usr/bin/python

from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
from ryu.ofproto.ofproto_v1_3 import OFP_VERSION
from ryu.ofproto import ether
import logging
LOG = logging.getLogger('ryu.app.ofctl_rest_listener')
LOG.setLevel(logging.DEBUG)

#
#XML, requests
#
import xml.etree.ElementTree as ET 
import subprocess
import re
#
#REST, Control plane classes
#
from rest import REST
from detach import *
from control_rab import *
from s1ap import *
from nas import *
from p2p_info import *
from vlan_routing import *
#
#For benchmarking
#
import timeit
import time

#for installing new package
import apt
import sys
import os

class AccessSwitchGtp:
  ##constants
  _SCRIPTS="/usr/local/src/simeca/start_scripts"
  _debug = 0

  _OVS_OFCTL = "ovs-ofctl"
  _GTP_APP_PORT = 2152
  _GTP = 4
  _DECAP_PORT = _GTP+1
  _ENCAP_PORT = _GTP+2
  ################

  #P2P  
  _p2p_list = [] #list of attached UE and its bearer info

  dpset = None
  access_switches = None
  switchname_to_dpid = None

  def __init__ (self, dpset, switchname_to_dpid, access_switches):
    LOG.debug("Create Access Switch ....")
    self.dpset = dpset #local datapath (switch) id
    self.access_switches = access_switches
    self.switchname_to_dpid = switchname_to_dpid

    #Get MAC
    self._get_MACs()
   
  '''
  Get MAC addresses of SGW, ENBs associated with AccessSwitches.
  '''
  def _get_MACs(self):
    LOG.debug("getting MACs...")
    domain_name = subprocess.check_output(["hostname | sed s/`hostname -s`.//"], shell=True).rstrip()

    #SGW
    SGW_NODE = "sgw.%s" % domain_name
    ssh_p = subprocess.Popen(["ssh", SGW_NODE, "ifconfig | grep -B1 192.168.4.20"], stdout=subprocess.PIPE)
    sgw_mac = re.search(r'HWaddr (.*)',ssh_p.communicate()[0]).group(1).split()[0]
    for a in self.access_switches:
        self.access_switches[a]['sgw_mac'] = sgw_mac

    #ENB
    for a in self.access_switches:
        index = a[6:7] 
	#print "Access =%s" % a
        enb_ulr = "enb%s.%s" % (index,domain_name)
        if index=="1":
            enb_ulr = "penb1.%s" % (domain_name)
        physical_logical_inf_map = subprocess.check_output(['ssh -o StrictHostKeyChecking=no %s "cd %s && ./get_interface_map.pl"'% (enb_ulr, self._SCRIPTS)], shell=True)
        enb_mac = ":".join(re.findall(r'.{1,2}',re.search(r"net-d-enb" + str(index) + r" -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(3)))
        self.access_switches[a]['enb_mac'] = enb_mac

  def _add_flow(self, datapath, priority, matches, actions):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
	
    if isinstance(matches, list):
        for match in matches:	
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                              match=match, instructions=inst)
            datapath.send_msg(mod)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                              match=matches, instructions=inst)
        datapath.send_msg(mod)
			
  def _get_dp_from_switch_name(self, switch_name):
    dp = self.dpset.get(int(self.switchname_to_dpid[switch_name]))
    if dp is None:
      print "DP of switch name %s is invalid!" % switch_name
      return None, None, None
    return dp, dp.ofproto, dp.ofproto_parser

  '''
  Push bridging flows for ALL AccessSwitches
  '''
  def push_flows_bridging_ryu(self):
    '''
    ovs-ofctl add-flow br0 in_port=$net_d_enb1,priority=2,actions=output:$net_d
    ovs-ofctl add-flow br0 in_port=$net_d_enb2,priority=2,actions=output:$net_d
    ovs-ofctl add-flow br0 in_port=$net_d,priority=2,actions=output:$net_d_enb1
    ovs-ofctl add-flow br0 in_port=$net_d,priority=2,actions=output:$net_d_enb2
    '''
    LOG.info("Pushing bridging flows on access switches ...")
    LOG.debug("Access switches: %s" %self.access_switches)
    for switch_name in self.access_switches:
      LOG.info("*****CONTROLLER: Pushing Layer 2 bridging flows for Access switch: %s ...*****" % switch_name)
      switch = self.access_switches[switch_name]
      dp, of, ofp = self._get_dp_from_switch_name(switch_name)
      matches = []
      actions = []
      matches.append(ofp.OFPMatch(in_port=switch['net-d-enb']))
      actions.append(ofp.OFPActionOutput(switch['net-d']))
      self._add_flow(dp,2,matches,actions)

      matches = []
      actions = []
      matches.append(ofp.OFPMatch(in_port=switch['net-d']))
      actions.append(ofp.OFPActionOutput(switch['net-d-enb']))
      self._add_flow(dp,2,matches,actions)


  

  #flows for src enb (input_port) to dst enb (output_port)
  #def _push_flows_P2P_ryu(self, input_port, output_port, sgw_teid, enb_teid, sgw_ip, enb_ip, sgw_mac, enb_mac, src_ip, dst_ip):
  #def push_flows_P2P_ryu(self, as1_name, as2_name, netd_port, gtp_port, sgw1_teid, enb1_teid, sgw2_teid, enb2_teid, sgw_ip, enb1_ip, enb2_ip, sgw_mac, src_ip, dst_ip):

  #!!!Working both: either A or B originates traffic
  def push_flows_P2P_ryu(self, as1_name, as2_name, sgw1_teid, enb1_teid, sgw2_teid, enb2_teid, sgw_ip, src_ip, dst_ip, enb1_location_ip, enb2_location_ip, enb1_ip, enb2_ip):
    '''
    #src enb to dst enb
    ovs-ofctl add-flow br0 in_port=$src_enb_inf,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,tun_id=$SGW_TEID,tun_src=$SRC_IP,tun_dst=$DST_IP,actions=mod_dl_dst:$ENB_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENB_TEID->tun_id","set_field:$ENB_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$dst_enb_inf

    #Hard coded:
    #Alice->Bob
    ovs-ofctl add-flow br0 in_port=$enb1_inf,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,tun_id=$SGW_TEID,tun_src=$ALICE_IP,tun_dst=$BOB_IP,actions=mod_dl_dst:$ENB2_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENB2_TEID->tun_id","set_field:$ENB2_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$enb2_inf
    #Bob->Alice
    ovs-ofctl add-flow br0 in_port=$enb2_inf,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,tun_id=$SGW_TEID,tun_src=$BOB_IP,tun_dst=$ALICE_IP,actions=mod_dl_dst:$ENB1_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENB1_TEID->tun_id","set_field:$ENB1_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$enb1_inf
    '''

    as1 = self.access_switches[as1_name]
    dp1, of1, ofp1 = self._get_dp_from_switch_name(as1_name)

    as2 = self.access_switches[as2_name]
    dp2, of2, ofp2 = self._get_dp_from_switch_name(as2_name)



    '''
    #alice->bob SGW->ENB2
    5. sudo ovs-ofctl add-flow br0 in_port=$as1['net-d-enb'],priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,actions=output:$gtp_port
    6. sudo ovs-ofctl add-flow br0 in_port=$gtp_port,priority=3,tun_id=$SGW1_TEID,tun_src=$ALICE_IP,tun_dst=$BOB_IP,actions=output:$gtp_decap_port
    7. sudo ovs-ofctl add-flow br0 in_port=$gtp_decap_port,priority=3,eth_type=$IP_TYPE,nw_src=$ALICE_IP,nw_dst=$BOB_IP,actions=mod_dl_dst:$ENB2_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENB2_TEID->tun_id","set_field:$ENB2_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$gtp_encap_port
    8. sudo ovs-ofctl add-flow br0 in_port=$gtp_encap_port,priority=3,eth_type=$IP_TYPE,nw_src=$SGW_IP,nw_dst=$ENB2_IP,actions=mod_tp_dst:$GTP_PORT,mod_tp_src:$GTP_PORT,output:$as2['net-d-enb']
    '''

    print "******P2P: Pushing flows from Alice to Bob, SGW->eNB2 direction*****"
    #5 (already installed in flows_uplink_ryu uppon attach)
    #match = ofp.OFPMatch(in_port=as1['net-d-enb'], eth_type=ether.ETH_TYPE_IP, ip_proto=17, udp_dst=self._GTP_APP_PORT)
    #actions = []
    #actions.append(ofp.OFPActionOutput(as1['gtp']))
    #self._add_flow(dp1,3,match,actions)
    
    #========================Originate: UE1 -> AS2===================#
    #At AS1-UL: ue1 originates -> enb2 (similar to uplink_ryu, however, dst_mac is now target enb's MAC)
    match = ofp1.OFPMatch(in_port=as1['gtp'], tunnel_id=sgw1_teid, tun_src=src_ip, tun_dst=dst_ip)
    actions = []
    #print "AS2's net-d-enb-mac = " , as2['net-d-enb-mac']
    actions.append(ofp1.OFPActionSetField(eth_dst=as2['net-d-enb-mac']))
    actions.append(ofp1.OFPActionOutput(as1['gtp_decap_port']))
    self._add_flow(dp1,3,match,actions)
    

    #!! pkts originating from UE have src IP = UE's IP, destination IP = target UE's IP/server's IP
    #   pkts returning from UE (eg, ping replies) have src IP = UE's IP, dst IP = target enb's location IP.
    #on access 1, returning pkts now have destination IP is target enb's location IP.
    #This is different from uplink flows as uplink pkts originated from UE have server/target UE's IP but not destination enb's location IP.
    #Therefore this flow rule
    #At AS1-UL:
    
    actions = []
    match = ofp1.OFPMatch(in_port=as1['gtp_decap_port'], eth_type=ether.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=enb2_location_ip)
    actions.append(ofp1.OFPActionSetField(ipv4_src=enb1_location_ip))
    actions.append(ofp1.OFPActionOutput(as1['offload'])) #working
    self._add_flow(dp1,3,match,actions)
    

    #ue1->enb2: From src's as to dst's as: replace as's IP with UE's IP
    #At AS2-DL:
    match = ofp2.OFPMatch(in_port=as2['offload'], eth_type=ether.ETH_TYPE_IP, ipv4_src=enb1_location_ip, ipv4_dst=enb2_location_ip)
    actions = []
    actions.append(ofp2.OFPActionSetField(eth_dst=as2['enb_mac']))
    actions.append(ofp2.OFPActionSetField(eth_src=as2['sgw_mac']))
    actions.append(ofp2.OFPActionSetField(ipv4_dst=dst_ip))
    actions.append(ofp2.OFPActionSetField(ipv4_src=src_ip))
    actions.append(ofp2.OFPActionSetField(tunnel_id=enb2_teid))
    actions.append(ofp2.OFPActionSetField(tun_dst=enb2_ip))
    actions.append(ofp2.OFPActionSetField(tun_src=sgw_ip))
    actions.append(ofp2.OFPActionOutput(as2['gtp_encap_port']))
    self._add_flow(dp2,3,match,actions)
    #To downlink_flow ... to eNB
    #============================================================#

    #===============================Replies: AS2 -> UE1===================#
    #At AS2 - UL: ue2 replies -> enb1 (similar to uplink_ryu, however, dst_mac is now target enb's MAC)
    match = ofp2.OFPMatch(in_port=as2['gtp'], tunnel_id=sgw2_teid, tun_src=dst_ip, tun_dst=src_ip)
    actions = []
    actions.append(ofp2.OFPActionSetField(eth_dst=as1['net-d-enb-mac']))
    actions.append(ofp2.OFPActionSetField(tun_dst=enb1_location_ip))
    actions.append(ofp2.OFPActionOutput(as2['gtp_decap_port']))
    self._add_flow(dp2,3,match,actions)

    #on access 2, returning pkts now have destination IP is source enb's location IP.
    #This is different from uplink flows as uplink pkts originated from UE have server/target UE's IP but not source enb's location IP.
    #Therefore this flow rule
    #At AS2 - UL:
    actions = []
    match = ofp2.OFPMatch(in_port=as2['gtp_decap_port'], eth_type=ether.ETH_TYPE_IP, ipv4_src=dst_ip, ipv4_dst=enb1_location_ip)
    actions.append(ofp2.OFPActionSetField(ipv4_src=enb2_location_ip))
    actions.append(ofp2.OFPActionOutput(as2['offload'])) #working
    self._add_flow(dp2,3,match,actions)
    
    
    #At AS1 - DL: enb2-> enb1: Returning downlink pkts: replace src's IP with target UE's IP.
    match = ofp1.OFPMatch(in_port=as1['offload'], eth_type=ether.ETH_TYPE_IP, ipv4_src=enb2_location_ip, ipv4_dst=enb1_location_ip)
    actions = []
    actions.append(ofp1.OFPActionSetField(eth_dst=as1['enb_mac']))
    actions.append(ofp1.OFPActionSetField(eth_src=as1['sgw_mac']))
    actions.append(ofp1.OFPActionSetField(ipv4_dst=src_ip))
    actions.append(ofp1.OFPActionSetField(ipv4_src=dst_ip))
    actions.append(ofp1.OFPActionSetField(tunnel_id=enb1_teid))
    actions.append(ofp1.OFPActionSetField(tun_dst=enb1_ip))
    actions.append(ofp1.OFPActionSetField(tun_src=sgw_ip))
    actions.append(ofp1.OFPActionOutput(as1['gtp_encap_port']))
    self._add_flow(dp1,3,match,actions)
    #==========================================================#


       

  #flows for uplink (ovs->offloading server), assuming OFFLOAD SERVER's MAC is known
  def push_flows_uplink_ryu(self, switch_name, sgw_teid, ue_ip, server_ip, server_mac):
    '''
    ovs-ofctl add-flow br0 in_port=$enb_inf,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,actions=output:$GTP
    ovs-ofctl add-flow br0 in_port=$GTP,priority=3,tun_id=$SGW_TEID,tun_src=$ALICE_IP,tun_dst=$OFF_IP,actions=mod_dl_dst:$OFF_MAC,output:$DECAP
    #ovs-ofctl add-flow br0 in_port=$DECAP,priority=3,eth_type=$IP_TYPE,nw_src=$ALICE_IP,nw_dst=$OFF_IP,actions=output:$offload_inf
    ovs-ofctl add-flow br0 in_port=$GTP,priority=2,actions=output:$sgw_inf
    '''
    print "*****CONTROLLER: Pushing UPLINK flows for UE %s, offloading server %s, sgw-gtpid %s, on switch %s ....." % (ue_ip,server_ip,sgw_teid, switch_name)
    switch = self.access_switches[switch_name]
    dp, of, ofp = self._get_dp_from_switch_name(switch_name)

    #1
    match = ofp.OFPMatch(in_port=switch['net-d-enb'],eth_type=ether.ETH_TYPE_IP,ip_proto=17,udp_dst=self._GTP_APP_PORT)
    actions = []
    actions.append(ofp.OFPActionOutput(switch['gtp']))
    self._add_flow(dp,3,match,actions)

    #2
    #TODO: defer #2 and #4 installation until server's information (IP, MAC) is known
    match = ofp.OFPMatch(in_port=switch['gtp'],tunnel_id=sgw_teid,tun_src=ue_ip,tun_dst=server_ip)
    actions = []
    actions.append(ofp.OFPActionSetField(eth_dst=server_mac))
    actions.append(ofp.OFPActionOutput(switch['gtp_decap_port']))
    self._add_flow(dp,3,match,actions)

    #4
    match = ofp.OFPMatch(in_port=switch['gtp'])
    actions = []
    actions.append(ofp.OFPActionOutput(switch['net-d']))
    self._add_flow(dp,2,match,actions)



  #flows for downlink (ovs->enb). Assumming ENB and SGW's MACs are known.
  def push_flows_downlink_ryu(self, switch_name, enb_teid, enb_ip, sgw_ip, ue_ip, enb_location_ip):
    '''
    ovs-ofctl add-flow br0 in_port=$offload_inf,priority=2,eth_type=$IP_TYPE,actions=mod_dl_dst:$ENODEB_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENODEB_TEID->tun_id","set_field:$ENODEB_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$ENCAP
    ovs-ofctl add-flow br0 in_port=$ENCAP,priority=2,eth_type=$IP_TYPE,actions=output:$enb_inf   
    '''
    print "******Pushing DOWNLINK flows for eNB GTPID %s, eNB IP %s, sgw IP %s, on switch %s ....." % (enb_teid, enb_ip, sgw_ip, switch_name)
    switch = self.access_switches[switch_name]
    dp, of, ofp = self._get_dp_from_switch_name(switch_name)


    #1
    #match = ofp.OFPMatch(in_port=switch['offload'],eth_type=ether.ETH_TYPE_IP, ipv4_dst=enb_location_ip)
    #either in_port=switch['offload'] or in_port=switch['net-d']
    match = ofp.OFPMatch(in_port=switch['offload'],eth_type=ether.ETH_TYPE_IP, ipv4_dst=enb_location_ip)
    actions = []
    actions.append(ofp.OFPActionSetField(eth_dst=switch['enb_mac']))
    actions.append(ofp.OFPActionSetField(eth_src=switch['sgw_mac']))
    actions.append(ofp.OFPActionSetField(ipv4_dst=ue_ip))
    actions.append(ofp.OFPActionSetField(tunnel_id=enb_teid))
    actions.append(ofp.OFPActionSetField(tun_dst=enb_ip))
    actions.append(ofp.OFPActionSetField(tun_src=sgw_ip))
    actions.append(ofp.OFPActionOutput(switch['gtp_encap_port']))
    self._add_flow(dp,3,match,actions)


    #2 normal traffic
    match = ofp.OFPMatch(in_port=switch['gtp_encap_port'],eth_type=ether.ETH_TYPE_IP)
    actions = []
    actions.append(ofp.OFPActionOutput(switch['net-d-enb']))
    self._add_flow(dp,2,match,actions)


  


  def _del_flows_ryu(self):
    for switch_name in self.access_switches:
        dp, of, ofp = self._get_dp_from_switch_name(switch_name)
        empty_match = ofp.OFPMatch()
        instructions = []
        table_id = 0 #remove flows in table 0 only!!
        flow_mod = self._remove_table_flows(dp, table_id,
                                empty_match, instructions)
        print "Deleting all flow entries in table %s of switch %s ..." % (table_id, switch_name)
        dp.send_msg(flow_mod)


  def _remove_table_flows(self, datapath, table_id, match, instructions):
      """Create OFP flow mod message to remove flows from table."""
      ofproto = datapath.ofproto
      flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                    ofproto.OFPFC_DELETE, 0, 0,
                                                    1,
                                                    ofproto.OFPCML_NO_BUFFER,
                                                    ofproto.OFPP_ANY,
                                                    OFPG_ANY, 0,
                                                    match, instructions)
      return flow_mod


  
