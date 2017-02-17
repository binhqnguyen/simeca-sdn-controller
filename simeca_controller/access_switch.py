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

class AccessSwitch:
  ##constants
  _debug = 0

  _OVS_OFCTL = "ovs-ofctl"
  _GTP_PORT = 2152
  _IP_TYPE = 0x0800
  _ARP_TYPE = 0x0806
  _GTP = 4
  _DECAP_PORT = _GTP+1
  _ENCAP_PORT = _GTP+2
  _ENB_NODE_NAME="enb1"
  _ENB2_NODE_NAME="enb2"
  _OFFLOAD_NODE_NAME="cloud"
  _BOB_NODE_NAME="bob"
  _ALICE_NODE_NAME="alice"
  ################

  #P2P  
  _p2p_list = [] #list of attached UE and its bearer info
  enb1_port = -1
  enb2_port = -1
  netd_port = -1
  sgw1_teid = 0x1111
  sgw2_teid = 0x1111
  enb1_teid = 0x1111
  enb2_teid = 0x1111

  #Vlan routing
  vlanrouting = None
  dpset = None
  access_switches = None

  def __init__ (self, dpset, access_switches):
    self.dpset = dpset #local datapath (switch) id
    self.access_switches = access_switches
   
    #self.vlanrouting = VlanRouting(self.dpset) 
    #self.vlanrouting.installPathVlan('192.168.3.101', '17778137524', '17779071330', 'VLAN_XX')


    self._get_MACs()
    self._set_default_route()
    self._build_database()
    self._del_flows_ryu()
    self._push_flows_bridging_ryu()
   
  '''
  Get MAC addresses of offloading server, enb's net-d, sgw's net-d-mme interfaces
  '''
  def _get_MACs(self):
    print "getting MACs..."
    domain_name = subprocess.check_output(["hostname | sed s/`hostname -s`.//"], shell=True).rstrip()

    #SGW
    self._SGW_NODE = "sgw.%s" % domain_name
    ssh_p = subprocess.Popen(["ssh", self._SGW_NODE, "ifconfig | grep -B1 192.168.4.20"], stdout=subprocess.PIPE)
    self._sgw_net_d_mme_mac = re.search(r'HWaddr (.*)',ssh_p.communicate()[0]).group(1).split()[0]
    for a in self.access_switches:
        self.access_switches[]

    self._ENB_NODE = "%s.%s" % (self._ENB_NODE_NAME,domain_name)
    self._ENB2_NODE = "%s.%s" % (self._ENB2_NODE_NAME,domain_name)
    self._OFFLOAD_NODE = "%s.%s" % (self._OFFLOAD_NODE_NAME,domain_name)
    self._BOB_NODE = "%s.%s" % (self._BOB_NODE_NAME,domain_name)
    self._ALICE_NODE = "%s.%s" % (self._ALICE_NODE_NAME,domain_name)
    ssh_p = subprocess.Popen(["ssh", self._ENB_NODE, "ifconfig | grep -B1 192.168.4.90"], stdout=subprocess.PIPE)
    self._enb_net_d_mac = re.search(r'HWaddr (.*)',ssh_p.communicate()[0]).group(1).split()[0]

    ssh_p = subprocess.Popen(["ssh", self._ENB2_NODE, "ifconfig | grep -B1 192.168.6.90"], stdout=subprocess.PIPE)
    self._enb2_net_d_mac = re.search(r'HWaddr (.*)',ssh_p.communicate()[0]).group(1).split()[0]

	
  '''
  Set default route for offloading node (after _get_MACs())
  '''
  def _set_default_route(self):
      print "_set_default_route"
      ssh_p = subprocess.Popen(["ssh", self._OFFLOAD_NODE, "/usr/local/etc/emulab/findif -i 192.168.10.11"], stdout=subprocess.PIPE)
      self._off1_offload_dev = ssh_p.communicate()[0]
      ssh_p = subprocess.Popen(["ssh", self._OFFLOAD_NODE, "sudo ip route add 192.168.3.0/24 dev %s" % self._off1_offload_dev], stdout=subprocess.PIPE)
      ssh_p.communicate()
	
  
   

  def _build_database(self):
    if os.path.isfile(self._USER_DB):
      user_db = open(self._USER_DB)


      line = user_db.readline()
      while line:
        if line.split()[0] != "":
          self._user_db.append(line.split()[0])
        line = user_db.readline()
    else: 
      print "NO DATABASE AVAILABLE!"

  #
  #Start sniffing
  #
  def _start_sniffing (self, interfaces):
    #
    #Parsing from tshark
    #
    tshark_out = subprocess.Popen(["sudo","tshark", "-i", interfaces, "-f", "sctp", "-T", "pdml"], stdout=subprocess.PIPE)
    packet_xml = ""
    file_xml = self._XML_HEADER
    for line in iter(tshark_out.stdout.readline, ""):
      packet_xml += line
      file_xml += line
      if re.match(r'</packet>',line):
        packet_xml += self._XML_END
        self.tshark_xml.write(file_xml)
        self._parse_packet(packet_xml)
        packet_xml = self._XML_HEADER
    #add footer of XML file
    self.tshark_xml.write(self._XML_END)

  #
  #Contact REST listener (controller) to add downlink flow for an attached UE 
  #
  def _send_add_downlink_flow(self):
    RAB_record = self.RAB_Information   
    ue_ip = getattr(RAB_record,"ue_ip")
    enb_gtpid = getattr(RAB_record,"e_gtp_id")
    #if packets are destined to ue_ip:
    # - GTP-encap with GTPID is enb_gtpid
    # - send to all ports on eNBs side.
    #Now: dummy REST message.
    ue_mme_id_mod = long(RAB_record.ue_mme_id) % 1000
    flow = {
      'match':{
        'dl_type':2048,
        'nw_dst':ue_ip
        },
      'idle_timeout':ue_mme_id_mod,
      'hard_timeout':333,
      'actions':[
        {
        "type":"OUTPUT",
        "port":enb_gtpid
        }
      ]
    }
	#self.rest_history.write("***add - " + str(flow))
    #Add the UE's record to list
    self.record_list.append(RAB_record)
    #print "sending add_flow = %s " % flow
    return self.rest.add_flows(self.local_dpid, flow)

  #
  #Contact REST listener (controller) to delete a downlink flow for a detached UE 
  #
  def _send_del_downlink_flow(self, ue_mme_id, ue_enb_id):
    #retrieve information of the attached UE
    ue_to_delete = None
    for record in self.record_list:
      if record.ue_mme_id == ue_mme_id and record.ue_enb_id == ue_enb_id:
        ue_to_delete = record
        break
    if ue_to_delete == None:
      print "Can't find UE %s %s in records list:" % (ue_mme_id, ue_enb_id)
      print self.record_list
      return None
    else:
      #delete matched flow from the flow table.
      flow = {
        "match":{
          "dl_type":"2048",
          "nw_dst":ue_to_delete.ue_ip
        },
        "actions":[
          {
            "type":"OUTPUT",
            "port":ue_to_delete.e_gtp_id
          }
        ]
      }
	  #self.rest_history.write("***delete - " + str(flow))
      #remove the UE's record from list
      self.record_list.remove(ue_to_delete)
      #print "sending del_flow = %s" % flow
      print "Detached: ue_mme_id = %s, ue_enb_id = %s, ue_ip = %s" % (ue_to_delete.ue_mme_id, ue_to_delete.ue_enb_id, ue_to_delete.ue_ip)
      return self.rest.del_matching_flows(self.local_dpid, flow)

  #
  #Parse NAS InitialContextSetupRequest messge and return NAS_RAB_setup_request.
  #
  def _process_rab_init_request(self, init_request, pkt_cnt):
    TAI = {}
    GUTI = {}
    LAI = {}
    pdn = {}
    s1ap_rab_request = None

    msg_text = init_request[0].get("show")
    #S1AP and NAS ID.
    ue_mme_id = init_request[0].findall(".//field[@name='s1ap.MME_UE_S1AP_ID']")[0].get("show") if init_request[0].findall(".//field[@name='s1ap.MME_UE_S1AP_ID']") else None
    ue_enb_id = init_request[0].findall(".//field[@name='s1ap.ENB_UE_S1AP_ID']")[0].get("show") if init_request[0].findall(".//field[@name='s1ap.ENB_UE_S1AP_ID']") else None

    #enb-sgw tunnel information
    s_gtp_id = init_request[0].findall(".//field[@name='s1ap.gTP_TEID']")[0].get("value") if init_request[0].findall(".//field[@name='s1ap.gTP_TEID']") else None
    sgw_ip = init_request[0].findall(".//field[@name='s1ap.transportLayerAddressIPv4']")[0].get("show") if init_request[0].findall(".//field[@name='s1ap.transportLayerAddressIPv4']") else  None
    if init_request[0].findall(".//field[@name='nas_eps.esm_pdn_type']"):
      pdn["type"] = init_request[0].findall(".//field[@name='nas_eps.esm_pdn_type']")[0].get("show")
    pdn["address"] = init_request[0].findall(".//field[@name='nas_eps.esm.pdn_ipv4']")[0].get("show")


    #LTE TAI
    TAI["MMC"] = init_request[0].findall(".//field[@name='e212.mcc']")[0].get("show") if init_request[0].findall(".//field[@name='e212.mcc']") else  None
    TAI["MNC"] = init_request[0].findall(".//field[@name='e212.mnc']")[0].get("show") if init_request[0].findall(".//field[@name='e212.mnc']") else  None 
    TAI["TAC"] = init_request[0].findall(".//field[@name='nas_eps.emm.tai_tac']")[0].get("show") if init_request[0].findall(".//field[@name='nas_eps.emm.tai_tac']") else None
    
    #LTE GUTI
    GUTI["MMC"] = init_request[0].findall(".//field[@name='e212.mcc']")[0].get("show") if init_request[0].findall(".//field[@name='e212.mcc']") else  None
    GUTI["MNC"] = init_request[0].findall(".//field[@name='e212.mnc']")[0].get("show") if init_request[0].findall(".//field[@name='e212.mnc']") else None
    GUTI["MME_GID"] = init_request[0].findall(".//field[@name='nas_eps.emm.mme_grp_id']")[0].get("show") if init_request[0].findall(".//field[@name='nas_eps.emm.mme_grp_id']") else None
    GUTI["MME_CODE"] = init_request[0].findall(".//field[@name='nas_eps.emm.mme_code']")[0].get("show") if  init_request[0].findall(".//field[@name='nas_eps.emm.mme_code']")  else  None
    GUTI["M_TMSI"] = init_request[0].findall(".//field[@name='nas_eps.emm.m_tmsi']")[0].get("show") if  init_request[0].findall(".//field[@name='nas_eps.emm.m_tmsi']") else None

    #GSM LAI
    lai = init_request[0].findall(".//field[@show='Location area identification']")
    if lai:
      LAI["MMC"] = lai[0].findall(".//field[@name='e212.mcc']")[0].get("show") if lai[0].findall(".//field[@name='e212.mcc']") else  None
      LAI["MNC"] = lai[0].findall(".//field[@name='e212.mnc']")[0].get("show") if lai[0].findall(".//field[@name='e212.mnc']") else  None
      LAI["LAC"] = lai[0].findall(".//field[@name='gsm_a.lac']")[0].get("show") if  lai[0].findall(".//field[@name='gsm_a.lac']") else None
    else:
      LAI["MMC"] = None
      LAI["MNC"] = None
      LAI["LAC"] = None

    IMSI = init_request[0].findall(".//field[@name='nas_eps.emm.imsi']")[0].get("show") if init_request[0].findall(".//field[@name='nas_eps.emm.imsi']") else  None

    #if (ue_mme_id and ue_enb_id and s_gtp_id and TAI and GUTI and LAI and pdn):
    NAS_request = NAS_RAB_setup_request(s_gtp_id, sgw_ip, TAI, GUTI, LAI, pdn, IMSI)
    s1ap_rab_request = S1AP(pkt_cnt, msg_text, ue_mme_id, ue_enb_id, NAS_request)
    if (s1ap_rab_request):
      #print "s1ap-rab-request:\n"
      #s1ap_rab_request.print_all()
      return s1ap_rab_request
    return None

  #
  #Parse NAS InitialContextSetupResponse messge and return NAS_RAB_setup_response.
  #
  def _process_rab_init_response(self, init_response, pkt_cnt):
    msg_text = init_response[0].get("show")

    ue_mme_id = init_response[0].findall(".//field[@name='s1ap.MME_UE_S1AP_ID']")[0].get("show") if init_response[0].findall(".//field[@name='s1ap.MME_UE_S1AP_ID']") else None
    ue_enb_id = init_response[0].findall(".//field[@name='s1ap.ENB_UE_S1AP_ID']")[0].get("show") if init_response[0].findall(".//field[@name='s1ap.ENB_UE_S1AP_ID']") else None
    e_gtp_id = init_response[0].findall(".//field[@name='s1ap.gTP_TEID']")[0].get("value") if init_response[0].findall(".//field[@name='s1ap.gTP_TEID']") else None
    enb_ip = init_response[0].findall(".//field[@name='s1ap.transportLayerAddressIPv4']")[0].get("show") if init_response[0].findall(".//field[@name='s1ap.transportLayerAddressIPv4']") else None

    #if (ue_mme_id and ue_enb_id and e_gtp_id and enb_ip):
    NAS_response = NAS_RAB_setup_response(e_gtp_id, enb_ip)
    s1ap_rab_response = S1AP(pkt_cnt, msg_text, ue_mme_id, ue_enb_id, NAS_response)
    if (s1ap_rab_response):
      return s1ap_rab_response
    return None

  #
  #Merge a NAS init msg with a NAS response msg to form a database entry.
  #
  def _merge_init_response(self):
    for s1ap_request in self.S1AP_init_request:
      for s1ap_response in self.S1AP_init_response:
        ##match found
        if not s1ap_request or not s1ap_response:
				#print "request= %s response= %s" % (s1ap_request, s1ap_response)
          continue
        if (s1ap_request.ue_mme_id == s1ap_response.ue_mme_id and s1ap_request.ue_enb_id == s1ap_response.ue_enb_id):
          print "-----------------------"
          print "UE attaches: # %d" % self.record_cnt
          print "-----------------------"
          self.record_cnt += 1
          control_rab_info = Control_RAB_Information(s1ap_request.ue_mme_id, s1ap_request.ue_enb_id, s1ap_request.nas.pdn["address"], s1ap_response.nas.e_gtp_id, s1ap_request.nas.s_gtp_id, s1ap_response.nas.enb_ip, s1ap_request.nas.sgw_ip, s1ap_request.nas.TAI, s1ap_request.nas.LAI, s1ap_request.nas.GUTI)
          #remove s1ap_request/response.
          self.S1AP_init_request.remove(s1ap_request)
          self.S1AP_init_response.remove(s1ap_response)
          return control_rab_info
    print "No match found!"
    return None

  def _process_s1ap_message(self, s1ap_msg):
    #get s1ap message type
    msg_type = s1ap_msg[0].findall(".//field[@name='nas_eps.nas_msg_emm_type']")[0].get("value") if s1ap_msg[0].findall(".//field[@name='nas_eps.nas_msg_emm_type']") else None
    #print "msg_type =  %s" % msg_type
    if msg_type:
      ue_mme_id = s1ap_msg[0].findall(".//field[@name='s1ap.MME_UE_S1AP_ID']")[0].get("show") if s1ap_msg[0].findall(".//field[@name='s1ap.MME_UE_S1AP_ID']") else None
      ue_enb_id = s1ap_msg[0].findall(".//field[@name='s1ap.ENB_UE_S1AP_ID']")[0].get("show") if s1ap_msg[0].findall(".//field[@name='s1ap.ENB_UE_S1AP_ID']") else None

      #detach request
      if msg_type == str(Detach_request.DETACH_REQUEST_MSG_TYPE):
        switch_off = s1ap_msg[0].findall(".//field[@name='nas_eps.emm.switch_off']")[0].get("value") if s1ap_msg[0].findall(".//field[@name='nas_eps.emm.switch_off']") else None
        detach_type_ul = s1ap_msg[0].findall(".//field[@name='nas_eps.emm.detach_type_ul']")[0].get("value") if s1ap_msg[0].findall(".//field[@name='nas_eps.emm.detach_type_ul']") else None
        type_of_id = s1ap_msg[0].findall(".//field[@name='nas_eps.emm.type_of_id']")[0].get("value") if s1ap_msg[0].findall(".//field[@name='nas_eps.emm.type_of_id']") else None
        IMSI= s1ap_msg[0].findall(".//field[@name='nas_eps.emm.imsi']")[0].get("show") if s1ap_msg[0].findall(".//field[@name='nas_eps.emm.imsi']") else None
        #process this detach request
        self._process_detach_request(Detach_request(ue_mme_id,ue_enb_id,switch_off,detach_type_ul,type_of_id,IMSI))

      #detach accept
      if msg_type == str(Detach_accept.DETACH_ACCEPT_MSG_TYPE):
        #process this detach accept
        self._process_detach_accept(Detach_accept(ue_mme_id,ue_enb_id))

  def _process_detach_request(self, detach_request):
    self.detach_requests.append(detach_request)
    self._merge_detach_request_accept()

  def _process_detach_accept(self, detach_accept):
    self.detach_accepts.append(detach_accept)
    self._merge_detach_request_accept()

  #
  #Scan through the detach request and accept list.
  #Match request/accept pair, delete downlink flows of detached UE.
  #
  def _merge_detach_request_accept(self):
    #print "merging detach request/accept"
    for detach_request in self.detach_requests:
      for detach_accept in self.detach_accepts:
        print "++++++++++++++++++++++"
        print "Detaching UE ue_mme_id %s" % detach_request.ue_mme_id
        print "++++++++++++++++++++++"
        if (detach_request.ue_mme_id == detach_accept.ue_mme_id and detach_request.ue_enb_id == detach_accept.ue_enb_id):
          ##Match found!
          self.detach_requests.remove(detach_request)
          self.detach_accepts.remove(detach_accept)
          #TODO: delete flow (how to match actions? or mayber just timeout eventually so no need to delete)
          #print self._send_del_downlink_flow(detach_request.ue_mme_id, detach_request.ue_enb_id)

  #
  #Parse the XML file which contains packet load produced by tshark -T pdml.
  #
  def parse_xml_file(self, xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    #Iterate through packets list.
    for packet in root.iter("packet"):
      init_request = None
      init_response = None
      self.pkt_cnt += 1

      #Default RAB setup messages from MME.
      init_request = packet.findall(".//field[@name='s1ap.InitialContextSetupRequest']")
      init_response = packet.findall(".//field[@name='s1ap.InitialContextSetupResponse']")
      #all other s1ap messages (detach request/response are just normal s1ap msges)
      s1ap_msg = packet.findall(".//proto[@name='s1ap']")
        
      #
      #s1ap.InitialContextSetupRequest message
      #
      if (init_request):
        self.S1AP_init_request.append(self._process_rab_init_request (init_request, self.pkt_cnt))

      #
      #s1ap.InitialContextSetupResponse message
      #
      if (init_response):
        self.S1AP_init_response.append(self._process_rab_init_response (init_response, self.pkt_cnt))

      #
      #Merge the init and response messages
      #
      if (self.S1AP_init_request and self.S1AP_init_response):
        self.RAB_Information = self._merge_init_response()
        #new record found
        if (self.RAB_Information):
          self.RAB_Information.print_all()
          #TODO: push-flows-downlink()
          RAB_record = self.RAB_Information   
          enb_ip = int ("0x"+getattr(RAB_record,"enb_ip"),16)
          enb_gtpid = int ("0x"+ getattr(RAB_record,"e_gtp_id"),16)
          sgw_ip = getattr(RAB_record,"sgw_ip")
          self._push_flows_downlink_ryu(enb_gtpid, enb_ip, sgw_ip)
          #print self.rest.dump_flows(self.local_dpid).text
          self.RAB_Information.print_all()
      #
      #Process other s1ap messages
      #
      if s1ap_msg:
        self._process_s1ap_message(s1ap_msg)
  #
  #Parse 1 xml packet.
  #
  def _parse_packet(self, packet):
    root = ET.fromstring(packet)

    #Iterate through packets list.
    for packet in root.iter("packet"):
      init_request = None
      init_response = None
      self.pkt_cnt += 1
      ### 
      start_1 = time.time()
      #Default RAB setup messages from MME.
      init_request = packet.findall(".//field[@name='s1ap.InitialContextSetupRequest']")
      init_response = packet.findall(".//field[@name='s1ap.InitialContextSetupResponse']")
      #all other s1ap messages (detach request/response are just normal s1ap msges)
      s1ap_msg = packet.findall(".//proto[@name='s1ap']")
      ###
      end_1 = time.time()
	  #print "DELTA_1=%f"%(end_1-start_1)
      #
      #s1ap.InitialContextSetupRequest message
      #
      if (init_request):
        self.S1AP_init_request.append(self._process_rab_init_request (init_request, self.pkt_cnt))

      #
      #s1ap.InitialContextSetupResponse message
      #
      if (init_response):
        self.S1AP_init_response.append(self._process_rab_init_response (init_response, self.pkt_cnt))
      ###BENCHMARKING
      #message (7) received.
      start_time = time.time()
	  #print "START=%f"%start_time

      #
      #Merge the init and response messages
      #
      if (self.S1AP_init_request and self.S1AP_init_response):
        self.RAB_Information = self._merge_init_response()
        #new record found
        if (self.RAB_Information):
          #TODO: 
          RAB_record = self.RAB_Information   
          enb_ip = getattr(RAB_record,"enb_ip")
          enb_gtpid = int ("0x"+getattr(RAB_record,"e_gtp_id"),16)
          sgw_gtpid = int ("0x"+getattr(RAB_record,"s_gtp_id"),16)
          sgw_ip = getattr(RAB_record,"sgw_ip")
          GUTI = getattr(RAB_record,"GUTI")
          M_TIMSI = GUTI["M_TMSI"]
          ue_ip = getattr(RAB_record,"ue_ip")
          self._p2p_list.append(p2p_info(ue_ip, enb_ip, sgw_ip, enb_gtpid, sgw_gtpid, M_TIMSI))
          #check if user is in database
          found = 0
		  #print M_TIMSI
          for mtimsi in self._user_db:
            if M_TIMSI == mtimsi:
              found = 1
              break
          if found == 1:
            print "Attached UE is a subscriber. Do offloading..."
            start_2 = time.time()
            self._push_flows_downlink_ryu(enb_gtpid, enb_ip, sgw_ip)
			#print "DELTA_PUSH_DL=%f"%(time.time()-start_2)
            start_3 = time.time()
            self._push_flows_uplink_ryu(sgw_gtpid, ue_ip, self._OFFLOAD_IP)
			#print "DELTA_PUSH_UL=%f"%(time.time()-start_3)
            start_4 = time.time()
            self._push_flows_ARP_ryu(self._OFFLOAD_IP)
			#print "DELTA_PUSH_ARP=%f"%(time.time()-start_4)

            ###BENCHMARKING
            ###push-flow commands sent out
            end_time = time.time()
			#print "END=%f"%end_time
			#print "DELTA_PUSH_ALL = %f" % (end_time-start_time)
          else:
            print "Attached UE is NOT a subscriber. Not doing offloading..."
          #print self._send_add_downlink_flow()
          #print self.rest.dump_flows(self.local_dpid).text
          self.RAB_Information.print_all()

          #BINH: remember 2 attached M_TIMSIs, create the P2P flows between them if 2 of them are in the user.dat.
          for p2p_1 in self._p2p_list:
              for p2p_2 in self._p2p_list:
                  ip_1 = getattr(p2p_1,"ue_ip")
                  ip_2 = getattr(p2p_2,"ue_ip")

                  if ip_1 == ip_2: 
                      continue

                  print "P2P checking for %s and %s" % (ip_1, ip_2)
                  sgw1_teid = getattr(p2p_1,"sgw_teid")
                  sgw2_teid = getattr(p2p_2,"sgw_teid")
                  enb1_teid = getattr(p2p_1,"enb_teid")
                  enb2_teid = getattr(p2p_2,"enb_teid")
                  enb1_ip = getattr(p2p_1,"enb_ip")
                  enb2_ip = getattr(p2p_2,"enb_ip")
                  sgw_ip = getattr(p2p_1,"sgw_ip")
                  if ip_1 in self._user_db and ip_2 in self._user_db:
                      #self._push_flows_P2P_ryu(self.enb1_port, self.enb2_port, self.netd_port, self._GTP, sgw1_teid, enb1_teid, sgw2_teid, enb2_teid, sgw_ip, enb1_ip, enb2_ip, self._sgw_net_d_mme_mac, self._enb_net_d_mac, self._enb2_net_d_mac, ip_1, ip_2)
                      print "sgw1_teid =%02x, sgw2_teid=%02x" % (sgw1_teid, sgw2_teid)
                      self._push_flows_P2P_ovs(self.enb1_port, self.enb2_port, self.netd_port, self._GTP, sgw1_teid, enb1_teid, sgw2_teid, enb2_teid, sgw_ip, enb1_ip, enb2_ip, self._sgw_net_d_mme_mac, self._enb_net_d_mac, self._enb2_net_d_mac, ip_1, ip_2)
                      self._p2p_list.remove(p2p_1)
                      self._p2p_list.remove(p2p_2)
                      print "p2p_list size %s" % len(self._p2p_list)
                
      #
      #Process other s1ap messages
      #
      if s1ap_msg:
        self._process_s1ap_message(s1ap_msg)

  def _install_pkg (self, pkg_name):
    cache = apt.cache.Cache()
    cache.update()
    pkg = cache[pkg_name]
    if pkg.is_installed:
      print "%s is already installed." % pkg_name
    else:
      pkg.mark_install()
      
      try:
        cache.commit()
      except Exception, arg:
        print >> sys.stderr, "Packet %s install failed." % pkg_name

  #Execute a command given the list of args of the command.
  def _execute(self, commands):
    return subprocess.check_output(commands)

  def _add_flow(self, datapath, priority, matches, actions):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
	
    #print "Match %s" % matches
    #print "Actions %s" % actions
    if isinstance(matches, list):
        for match in matches:	
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                              match=match, instructions=inst)
            datapath.send_msg(mod)
            #print "sent match=%s, instruction=%s, to datapath=%s"%(matches, inst, datapath)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                              match=matches, instructions=inst)
        #print "sent match=%s, instruction=%s, to datapath=%s"%(matches, inst, datapath)
        datapath.send_msg(mod)
			


  ##########OVS tunnelling manipulations########
  #Flows for normal traffic
  def _push_flows_bridging(self):
    '''
    ovs-ofctl add-flow br0 in_port=$enb_inf,priority=2,actions=output:$sgw_inf
    ovs-ofctl add-flow br0 in_port=$sgw_inf,priority=2,actions=output:$enb_inf
    '''
    print "*****CONTROLLER: Pushing Layer 2 bridging flows for OVS ...*****"
    uplink_flow = "in_port=%s,priority=2,actions=output:%s" % (self.enb_inf, self.sgw_inf)
    downlink_flow = "in_port=%s,priority=2,actions=output:%s" % (self.sgw_inf, self.enb_inf)
    self._execute ([self._OVS_OFCTL,"add-flow",self.local_dpid,uplink_flow])
    self._execute ([self._OVS_OFCTL,"add-flow",self.local_dpid,downlink_flow])

  def _push_flows_bridging_ryu(self):
    '''
    ovs-ofctl add-flow br0 in_port=$net_d_enb1,priority=2,actions=output:$net_d
    ovs-ofctl add-flow br0 in_port=$net_d_enb2,priority=2,actions=output:$net_d
    ovs-ofctl add-flow br0 in_port=$net_d,priority=2,actions=output:$net_d_enb1
    ovs-ofctl add-flow br0 in_port=$net_d,priority=2,actions=output:$net_d_enb2
    '''
    print "*****CONTROLLER: Pushing Layer 2 bridging flows for OVS ...*****"
    matches = []
    actions = []
    matches.append(self.parser.OFPMatch(in_port=self.enb_inf))
    matches.append(self.parser.OFPMatch(in_port=self.enb2_inf))
    actions.append(self.parser.OFPActionOutput(self.sgw_inf))
    self._add_flow(self.datapath,2,matches,actions)

    matches = []
    actions = []
    matches.append(self.parser.OFPMatch(in_port=self.sgw_inf))
    actions.append(self.parser.OFPActionOutput(self.enb_inf))
    actions.append(self.parser.OFPActionOutput(self.enb2_inf))
    self._add_flow(self.datapath,2,matches,actions)

  '''
  Set the default gateway for the offloading node for returning 
  packets destined for UE to go through the offload interface.
  '''
  def _set_default_gateway_in_offload_node(self):
		  #print "MANUALLY ADD ARP"
	ssh_p = subprocess.Popen(["ssh", self._OFFLOAD_NODE, "ifconfig | grep -B1 192.168.10.11"], stdout=subprocess.PIPE)
	self._off1_offload_interface = re.search(r'(.*) Link encap:',ssh_p.communicate()[0]).group(1).split()[0]
	#print "off1_offload_interface = %s" % self._off1_offload_interface
	p = subprocess.Popen(["ssh", self._OFFLOAD_NODE,"sudo ip route add 192.168.3.0/24 dev %s" % (self._off1_offload_interface)], stdout=subprocess.PIPE)
	p.communicate()

  #flows for ARPs
  def _push_flows_ARP(self, offload_ip):
    '''
    ovs-ofctl add-flow br0 in_port=$offload_inf,priority=2,eth_type=$ARP_TYPE,actions="set_field:$OFF_IP->tun_dst",output:$ENCAP
    ovs-ofctl add-flow br0 in_port=$ENCAP,priority=2,eth_type=$ARP_TYPE,actions=output:$offload_inf
    '''
    print "******Pushing APRS flows. Offloading server %s ....." % (offload_ip)
    uplink_flow = 'in_port=%s,priority=2,eth_type=%s,actions=set_field:%s->tun_dst,output:%d' % \
    (self.offload_inf, self._ARP_TYPE, offload_ip, self._ENCAP_PORT)
    downlink_flow = 'in_port=%d,priority=2,eth_type=%s,actions=output:%s' % \
    (self._ENCAP_PORT, self._ARP_TYPE, self.offload_inf)
    self._execute ([self._OVS_OFCTL,"add-flow",self.local_dpid,uplink_flow])
    self._execute ([self._OVS_OFCTL,"add-flow",self.local_dpid,downlink_flow])
    '''
	Manually let offloading server know how to answer to IP packets from UE
	'''
    self._set_default_gateway_in_offload_node()


  def _push_flows_ARP_ryu(self, offload_ip):
    '''
    ovs-ofctl add-flow br0 in_port=$offload_inf,priority=2,eth_type=$ARP_TYPE,actions="set_field:$OFF_IP->tun_dst",output:$ENCAP
    ovs-ofctl add-flow br0 in_port=$ENCAP,priority=2,eth_type=$ARP_TYPE,actions=output:$offload_inf
    '''
    print "******Pushing APRS flows. Offloading server %s ....." % (offload_ip)

    actions = []
    match = self.parser.OFPMatch(in_port=self.offload_inf,eth_type=self._ARP_TYPE)
    actions.append(self.parser.OFPActionSetField(tun_dst=offload_ip))
    actions.append(self.parser.OFPActionOutput(self._ENCAP_PORT))
    self._add_flow(self.datapath,2,match,actions)

    match = self.parser.OFPMatch(in_port=self._ENCAP_PORT,eth_type=self._ARP_TYPE)
    actions = []
    actions.append(self.parser.OFPActionOutput(self.offload_inf))
    self._add_flow(self.datapath,2,match,actions)
    self._set_default_gateway_in_offload_node()




  #flows for uplink (ovs->offloading server), assuming OFFLOAD SERVER's MAC is known
  def _push_flows_uplink(self, sgw_teid, ue_ip, offload_ip):
    '''
    ovs-ofctl add-flow br0 in_port=$enb_inf,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,actions=output:$GTP
    ovs-ofctl add-flow br0 in_port=$GTP,priority=3,tun_id=$SGW_TEID,tun_src=$ALICE_IP,tun_dst=$OFF_IP,actions=mod_dl_dst:$OFF_MAC,output:$DECAP
    ovs-ofctl add-flow br0 in_port=$DECAP,priority=3,eth_type=$IP_TYPE,nw_src=$ALICE_IP,nw_dst=$OFF_IP,actions=output:$offload_inf
    ovs-ofctl add-flow br0 in_port=$GTP,priority=2,actions=output:$sgw_inf
    '''
    print "******Pushing UPLINK flows for UE %s, offloading server %s, sgw-gtpid %s ....." % (ue_ip,offload_ip,sgw_teid)
    uplink_flow_to_gtp = 'in_port=%s,priority=3,eth_type=%s,nw_proto=17,tp_dst=%d,actions=output:%d' %\
    (self.enb_inf, self._IP_TYPE, self._GTP_PORT, self._GTP)
    uplink_flow_gtp = 'in_port=%d,priority=3,tun_id=%s,tun_src=%s,tun_dst=%s,actions=mod_dl_dst:%s,output:%d'%\
    (self._GTP, sgw_teid, ue_ip, offload_ip, self._off1_offload_mac, self._DECAP_PORT)
    uplink_flow_from_gtp = 'in_port=%d,priority=3,eth_type=%s,nw_src=%s,nw_dst=%s,actions=output:%s' %\
    (self._DECAP_PORT, self._IP_TYPE, ue_ip, offload_ip, self.offload_inf)
    uplink_normal_gtp = "in_port=%d,priority=2,actions=output:%s" % (self._GTP, self.sgw_inf)
    self._execute ([self._OVS_OFCTL,"add-flow",self.local_dpid,uplink_flow_to_gtp])
    self._execute ([self._OVS_OFCTL,"add-flow",self.local_dpid,uplink_flow_gtp])
    self._execute ([self._OVS_OFCTL,"add-flow",self.local_dpid,uplink_flow_from_gtp])
    self._execute ([self._OVS_OFCTL,"add-flow",self.local_dpid,uplink_normal_gtp])


  def _push_flows_P2P_ovs(self, enb1_port, enb2_port, netd_port, gtp_port, sgw1_teid, enb1_teid, sgw2_teid, enb2_teid, sgw_ip, enb1_ip, enb2_ip, sgw_mac, enb1_mac, enb2_mac, src_ip, dst_ip):
      print "****Pushing P2P flows *****"
      print "sgw1_teid=%02x, sgw2_teid=%02x"%(sgw1_teid,sgw2_teid)
      os.system("./p2p_on_withargs.sh %02x %02x %02x %02x %s %s %s"%(sgw1_teid,sgw2_teid,enb1_teid,enb2_teid,enb1_port, enb2_port, netd_port))

  #flows for src enb (input_port) to dst enb (output_port)
  #def _push_flows_P2P_ryu(self, input_port, output_port, sgw_teid, enb_teid, sgw_ip, enb_ip, sgw_mac, enb_mac, src_ip, dst_ip):
  def _push_flows_P2P_ryu(self, enb1_port, enb2_port, netd_port, gtp_port, sgw1_teid, enb1_teid, sgw2_teid, enb2_teid, sgw_ip, enb1_ip, enb2_ip, sgw_mac, enb1_mac, enb2_mac, src_ip, dst_ip):
    '''
    #src enb to dst enb
    ovs-ofctl add-flow br0 in_port=$src_enb_inf,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,tun_id=$SGW_TEID,tun_src=$SRC_IP,tun_dst=$DST_IP,actions=mod_dl_dst:$ENB_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENB_TEID->tun_id","set_field:$ENB_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$dst_enb_inf

    #Hard coded:
    #Alice->Bob
    ovs-ofctl add-flow br0 in_port=$enb1_inf,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,tun_id=$SGW_TEID,tun_src=$ALICE_IP,tun_dst=$BOB_IP,actions=mod_dl_dst:$ENB2_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENB2_TEID->tun_id","set_field:$ENB2_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$enb2_inf
    #Bob->Alice
    ovs-ofctl add-flow br0 in_port=$enb2_inf,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,tun_id=$SGW_TEID,tun_src=$BOB_IP,tun_dst=$ALICE_IP,actions=mod_dl_dst:$ENB1_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENB1_TEID->tun_id","set_field:$ENB1_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$enb1_inf
    '''

    print "******Pushing P2P flows for:"
    print "srcUEIp %s, dstUEIp %s"% (src_ip,dst_ip)
    print "Port in ENB1 %s, port in ENB2 %s, port EPC(to SGW) %s, gtp_port %s, encap %s, decap %s" % (enb1_port, enb2_port, netd_port, gtp_port, self._ENCAP_PORT, self._DECAP_PORT)
    print "SGW1_TEID %s, ENB1_TEID %s" % (sgw1_teid, enb1_teid)
    print "SGW2_TEID %s, ENB2_TEID %s" % (sgw2_teid, enb2_teid)
    print "ENB1 IP %s, ENB2 IP %s, SGW IP %s" % (enb1_ip, enb2_ip, sgw_ip)
    print "eNB1 MAC %s, eNB2 MAC %s, SGW MAC %s\n" % (enb1_mac, enb2_mac, sgw_mac)


    '''
    #Bridging, lower priority
    1. sudo ovs-ofctl add-flow br0 in_port=$enb1_port,priority=2,actions=output:$netd_port
    3. sudo ovs-ofctl add-flow br0 in_port=$enb2_port,priority=2,actions=output:$netd_port
    2. sudo ovs-ofctl add-flow br0 in_port=$netd_port,priority=2,actions=output:$enb1_port,output:$enb2_port
    '''
    print "******P2P: Pushing bridging flows, low priority*****"
    #1,2
    match = []
    match.append(self.parser.OFPMatch(in_port=enb1_port))
    match.append(self.parser.OFPMatch(in_port=enb2_port))
    actions = []
    actions.append(self.parser.OFPActionOutput(netd_port))
    self._add_flow(self.datapath,2,match,actions)
    
    #3
    match = self.parser.OFPMatch(in_port=netd_port)
    actions = []
    actions.append(self.parser.OFPActionOutput(enb1_port))
    actions.append(self.parser.OFPActionOutput(enb2_port))
    self._add_flow(self.datapath,2,match,actions)
    

    '''
    #Normal traffic, low priority
    4. sudo ovs-ofctl add-flow br0 in_port=$gtp_port,priority=2,actions=output:$netd_port
    '''
    print "******P2P: Pushing flow for normal traffic, low priority*****"
    #4
    match = self.parser.OFPMatch(in_port=gtp_port)
    actions = []
    actions.append(self.parser.OFPActionOutput(netd_port))
    self._add_flow(self.datapath,2,match,actions)
    

    '''
    #alice->bob SGW->ENB2
    5. sudo ovs-ofctl add-flow br0 in_port=$enb1_port,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,actions=output:$gtp_port
    6. sudo ovs-ofctl add-flow br0 in_port=$gtp_port,priority=3,tun_id=$SGW1_TEID,tun_src=$ALICE_IP,tun_dst=$BOB_IP,actions=output:$gtp_decap_port
    7. sudo ovs-ofctl add-flow br0 in_port=$gtp_decap_port,priority=3,eth_type=$IP_TYPE,nw_src=$ALICE_IP,nw_dst=$BOB_IP,actions=mod_dl_dst:$ENB2_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENB2_TEID->tun_id","set_field:$ENB2_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$gtp_encap_port
    8. sudo ovs-ofctl add-flow br0 in_port=$gtp_encap_port,priority=3,eth_type=$IP_TYPE,nw_src=$SGW_IP,nw_dst=$ENB2_IP,actions=mod_tp_dst:$GTP_PORT,mod_tp_src:$GTP_PORT,output:$enb2_port
    '''

    print "******P2P: Pushing flows from Alice to Bob, SGW->eNB2 direction*****"
    #5
    match = self.parser.OFPMatch(in_port=enb1_port, eth_type=self._IP_TYPE, ip_proto=17, udp_dst=self._GTP_PORT)
    actions = []
    actions.append(self.parser.OFPActionOutput(self._GTP))
    self._add_flow(self.datapath,3,match,actions)
    
    #6
    match = self.parser.OFPMatch(in_port=self._GTP, tunnel_id=sgw1_teid, tun_src=src_ip, tun_dst=dst_ip)
    actions = []
    actions.append(self.parser.OFPActionOutput(self._DECAP_PORT))
    self._add_flow(self.datapath,3,match,actions)

    #7
    match = self.parser.OFPMatch(in_port=self._DECAP_PORT, eth_type=self._IP_TYPE, ipv4_src=src_ip, ipv4_dst=dst_ip)
    actions = []
    actions.append(self.parser.OFPActionSetField(eth_dst=enb2_mac))
    actions.append(self.parser.OFPActionSetField(eth_src=sgw_mac))
    actions.append(self.parser.OFPActionSetField(tunnel_id=enb2_teid))
    actions.append(self.parser.OFPActionSetField(tun_dst=enb2_ip))
    actions.append(self.parser.OFPActionSetField(tun_src=sgw_ip))
    actions.append(self.parser.OFPActionOutput(self._ENCAP_PORT))
    self._add_flow(self.datapath,3,match,actions)

    #8
    #print "xx1"
    match = self.parser.OFPMatch(in_port=self._ENCAP_PORT, eth_type=self._IP_TYPE, ipv4_src=sgw_ip, ipv4_dst=enb2_ip)
    #match = self.parser.OFPMatch(in_port=self._ENCAP_PORT, eth_type=self._IP_TYPE)
    actions = []
    #actions.append(self.parser.OFPActionSetField(udp_src=self._GTP_PORT))
    #actions.append(self.parser.OFPActionSetField(udp_dst=self._GTP_PORT))
    actions.append(self.parser.OFPActionOutput(enb2_port))
    self._add_flow(self.datapath,3,match,actions)


    '''
    #alice->bob reply SGW->ENB1
    9. sudo ovs-ofctl add-flow br0 in_port=$enb2_port,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,actions=output:$gtp_port
    10. sudo ovs-ofctl add-flow br0 in_port=$gtp_port,priority=3,tun_id=$SGW2_TEID,tun_src=$BOB_IP,tun_dst=$ALICE_IP,actions=output:$gtp_decap_port
    11. sudo ovs-ofctl add-flow br0 in_port=$gtp_decap_port,priority=3,eth_type=$IP_TYPE,nw_src=$BOB_IP,nw_dst=$ALICE_IP,actions=mod_dl_dst:$ENB1_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENB1_TEID->tun_id","set_field:$ENB1_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$gtp_encap_port
    12. sudo ovs-ofctl add-flow br0 in_port=$gtp_encap_port,priority=3,eth_type=$IP_TYPE,nw_src=$SGW_IP,nw_dst=$ENB1_IP,actions=mod_tp_dst:$GTP_PORT,mod_tp_src:$GTP_PORT,output:$enb1_port
    '''
    print "******P2P: Pushing flows from Alice to Bob, SGW->eNB1 direction*****"
    #9
    match = self.parser.OFPMatch(in_port=enb2_port, eth_type=self._IP_TYPE, ip_proto=17, udp_dst=self._GTP_PORT)
    actions = []
    actions.append(self.parser.OFPActionOutput(self._GTP))
    self._add_flow(self.datapath,3,match,actions)
    
    #10
    match = self.parser.OFPMatch(in_port=self._GTP, tunnel_id=sgw2_teid, tun_src=dst_ip, tun_dst=src_ip)
    actions = []
    actions.append(self.parser.OFPActionOutput(self._DECAP_PORT))
    self._add_flow(self.datapath,3,match,actions)

    #11
    match = self.parser.OFPMatch(in_port=self._DECAP_PORT, eth_type=self._IP_TYPE, ipv4_src=dst_ip, ipv4_dst=src_ip)
    actions = []
    actions.append(self.parser.OFPActionSetField(eth_dst=enb1_mac))
    actions.append(self.parser.OFPActionSetField(eth_src=sgw_mac))
    actions.append(self.parser.OFPActionSetField(tunnel_id=enb1_teid))
    actions.append(self.parser.OFPActionSetField(tun_dst=enb1_ip))
    actions.append(self.parser.OFPActionSetField(tun_src=sgw_ip))
    actions.append(self.parser.OFPActionOutput(self._ENCAP_PORT))
    self._add_flow(self.datapath,3,match,actions)

    #12
    #print "xx2"
    match = self.parser.OFPMatch(in_port=self._ENCAP_PORT, eth_type=self._IP_TYPE, ipv4_src=sgw_ip, ipv4_dst=enb1_ip)
    actions = []
    #actions.append(self.parser.OFPActionSetField(udp_src=self._GTP_PORT))
    #actions.append(self.parser.OFPActionSetField(udp_dst=self._GTP_PORT))
    actions.append(self.parser.OFPActionOutput(enb1_port))
    self._add_flow(self.datapath,3,match,actions)


  #flows for uplink (ovs->offloading server), assuming OFFLOAD SERVER's MAC is known
  def _push_flows_uplink_ryu(self, sgw_teid, ue_ip, offload_ip):
    '''
    ovs-ofctl add-flow br0 in_port=$enb_inf,priority=3,eth_type=$IP_TYPE,nw_proto=17,tp_dst=$GTP_PORT,actions=output:$GTP
    ovs-ofctl add-flow br0 in_port=$GTP,priority=3,tun_id=$SGW_TEID,tun_src=$ALICE_IP,tun_dst=$OFF_IP,actions=mod_dl_dst:$OFF_MAC,output:$DECAP
    ovs-ofctl add-flow br0 in_port=$DECAP,priority=3,eth_type=$IP_TYPE,nw_src=$ALICE_IP,nw_dst=$OFF_IP,actions=output:$offload_inf
    ovs-ofctl add-flow br0 in_port=$GTP,priority=2,actions=output:$sgw_inf
    '''
    print "*****CONTROLLER: Pushing UPLINK flows for UE %s, offloading server %s, sgw-gtpid %s ....." % (ue_ip,offload_ip,sgw_teid)

    #1
    #match = self.parser.OFPMatch(in_port=self.enb_inf,eth_type=self._IP_TYPE,nw_proto=17,tp_dst=self._GTP_PORT)
    match = self.parser.OFPMatch(in_port=self.enb_inf,eth_type=self._IP_TYPE,ip_proto=17,udp_dst=self._GTP_PORT)
    actions = []
    actions.append(self.parser.OFPActionOutput(self._GTP))
    self._add_flow(self.datapath,3,match,actions)

    #2
    match = self.parser.OFPMatch(in_port=self._GTP,tunnel_id=sgw_teid,tun_src=ue_ip,tun_dst=offload_ip)
    actions = []
    actions.append(self.parser.OFPActionSetField(eth_dst=self._off1_offload_mac))
    actions.append(self.parser.OFPActionOutput(self._DECAP_PORT))
    self._add_flow(self.datapath,3,match,actions)

    #3
    match = self.parser.OFPMatch(in_port=self._DECAP_PORT,eth_type=self._IP_TYPE,ipv4_src=ue_ip,ipv4_dst=offload_ip)
    actions = []
    actions.append(self.parser.OFPActionOutput(self.offload_inf))
    self._add_flow(self.datapath,3,match,actions)

    #4
    match = self.parser.OFPMatch(in_port=self._GTP)
    actions = []
    actions.append(self.parser.OFPActionOutput(self.sgw_inf))
    self._add_flow(self.datapath,2,match,actions)


  #flows for downlink (ovs->enb). Assumming ENB and SGW's MACs are known.
  def _push_flows_downlink(self, enb_teid, enb_ip, sgw_ip):
    '''
    ovs-ofctl add-flow br0 in_port=$offload_inf,priority=2,eth_type=$IP_TYPE,actions=mod_dl_dst:$ENODEB_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENODEB_TEID->tun_id","set_field:$ENODEB_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$ENCAP
    ovs-ofctl add-flow br0 in_port=$ENCAP,priority=2,eth_type=$IP_TYPE,actions=output:$enb_inf   
    '''
    print "******Pushing DOWNLINK flows for eNB GTPID %s, eNB IP %s, sgw IP %s ....." % (enb_teid, enb_ip, sgw_ip)
    downlink_flow = 'in_port=%s,priority=2,eth_type=%s,actions=mod_dl_dst:%s,mod_dl_src=%s,set_field:%s->tun_id,set_field:%s->tun_dst,set_field:%s->tun_src,output:%d' %\
    (self.offload_inf, self._IP_TYPE, self._enb_net_d_mac, self._sgw_net_d_mme_mac, enb_teid, enb_ip, sgw_ip, self._ENCAP_PORT)
    downlink_flow_gtp = 'in_port=%d,priority=2,eth_type=%s,actions=output:%s' %\
    (self._ENCAP_PORT, self._IP_TYPE, self.enb_inf)
    self._execute ([self._OVS_OFCTL,"add-flow",self.local_dpid,downlink_flow])
    self._execute ([self._OVS_OFCTL,"add-flow",self.local_dpid,downlink_flow_gtp])


  #flows for downlink (ovs->enb). Assumming ENB and SGW's MACs are known.
  def _push_flows_downlink_ryu(self, enb_teid, enb_ip, sgw_ip):
    '''
    ovs-ofctl add-flow br0 in_port=$offload_inf,priority=2,eth_type=$IP_TYPE,actions=mod_dl_dst:$ENODEB_MAC,mod_dl_src=$SGW_MAC,"set_field:$ENODEB_TEID->tun_id","set_field:$ENODEB_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$ENCAP
    ovs-ofctl add-flow br0 in_port=$ENCAP,priority=2,eth_type=$IP_TYPE,actions=output:$enb_inf   
    '''
    print "******Pushing DOWNLINK flows for eNB GTPID %s, eNB IP %s, sgw IP %s ....." % (enb_teid, enb_ip, sgw_ip)

    #1
    match = self.parser.OFPMatch(in_port=self.offload_inf,eth_type=self._IP_TYPE)
    actions = []
    actions.append(self.parser.OFPActionSetField(eth_dst=self._enb_net_d_mac))
    actions.append(self.parser.OFPActionSetField(eth_src=self._sgw_net_d_mme_mac))
    actions.append(self.parser.OFPActionSetField(tunnel_id=enb_teid))
    actions.append(self.parser.OFPActionSetField(tun_dst=enb_ip))
    actions.append(self.parser.OFPActionSetField(tun_src=sgw_ip))
    actions.append(self.parser.OFPActionOutput(self._ENCAP_PORT))
    self._add_flow(self.datapath,2,match,actions)

    #2
    match = self.parser.OFPMatch(in_port=self._ENCAP_PORT,eth_type=self._IP_TYPE)
    actions = []
    actions.append(self.parser.OFPActionOutput(self.enb_inf))
    self._add_flow(self.datapath,2,match,actions)




  #reversely delete a downlink flow (when UE detaches)
  #def _del_downlink_flow(self, enb_teid, enb_ip, sgw_ip):

  def _del_flows(self):
    self._execute ([self._OVS_OFCTL,"del-flows",self.local_dpid])

  def _del_flows_ryu(self):
    empty_match = self.parser.OFPMatch()
    instructions = []
    table_id = 0 #remove flows in table 0 only!!
    flow_mod = self._remove_table_flows(self.datapath, table_id,
                                empty_match, instructions)
    print "Deleting all flow entries in table ", table_id
    self.datapath.send_msg(flow_mod)


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

  #################################
  def push_flow_test(self):
    '''
    OFF_MAC="00:02:b3:65:cd:49"
    OFF_IP="192.168.10.11"
    IP_TYPE=0x0800
    GTP_PORT=2152
    ALICE_IP="192.168.3.100"
    ARP_TYPE=0x0806
    ENODEB_MAC="00:04:23:b7:18:ff"
    ENODEB_IP="192.168.4.90"
    ENODEB_TEID=0x00000015
    SGW_MAC="00:04:23:b7:1b:cc"
    SGW_IP="192.168.4.20"
    '''
    print "Pushing bridging ...."
    self._push_flows_bridging()
    print "Pushing arps ...., offload_ip=%s" % self._OFFLOAD_IP
    self._push_flows_ARP(self._OFFLOAD_IP)
    print "Pushing uplink ...."
    self._push_flows_uplink(sgw_teid="0x4dc856f9", ue_ip="192.168.3.100", offload_ip=self._OFFLOAD_IP)
    print "Pushing downlink ...."
    self._push_flows_downlink(enb_teid="0x00000015", enb_ip="192.168.4.90", sgw_ip="192.168.4.20")
    print "flows:"
    print self._execute([self._OVS_OFCTL,"dump-flows",self.local_dpid])


if __name__ == "__main__":
  '''
  #Testing Sniffer
  if len(sys.argv) != 6:
    print "Parameters: <net-d-enb interface> <offload-server interface> <net-d-mme interface> <ovs public IP> <ovs controller port>"
    exit(1)

  enb_inf = str(sys.argv[1])
  offload_inf = str(sys.argv[2])
  sgw_inf = str(sys.argv[3])
  ovs_ip = str(sys.argv[4])
  ovs_port = str(sys.argv[5])

  #create sniffer
  bridge = "tcp:%s:%s" % (ovs_ip, ovs_port)
  sniffer = Sniffer(bridge, ovs_ip, enb_inf, sgw_inf, offload_inf,None)

  sniffer.start_sniffing("eth2")
  
  #sniffer.parse_from_file()
  #start listening
  #sniffer.push_flow_test()

  #
  #Benchmarking
  #
  #timeit.timeit(sniffer._parse_xml_file("S1AP.xml"))
  #print "%s %s" % (INTERFACES, OVS_IP)
  '''

  '''
  dpids = requests.get("http://%s:8080/stats/switches" % OVS_IP)
  print "Switch(es) ids = %s" % dpids.text

  #simply push flow to test REST.
  flow = {
    "match":{
      "dl_type":"2048",
      "nw_dst":ue_to_delete.ue_ip
    },
    "actions":[
      {
      "type":"OUTPUT",
      "port":ue_to_delete.e_gtp_id
      }
    ] 
  } 

  #sniffer = Sniffer(17779073986, OVS_IP)
  #sniffer.start_sniffing(INTERFACES)
  #sniffer.parse_xml_file("S1APs")
  '''
