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
from location_routing import *
from access_switch_gtp import *
#
#For benchmarking
#
import timeit
import time
import random

#for installing new package
import apt
import sys
import os

from ryu.app.wsgi import ControllerBase, WSGIApplication

class Sniffer():
  ##constants
  _debug = 0

  _XML_HEADER = "<?xml version=\"1.0\"?>\n\
                <?xml-stylesheet type=\"text/xsl\" href=\"pdml2html.xsl\"?>\n\
                <pdml version=\"0\" creator=\"wireshark/1.8.5\" time=\"Mon Jan 20 15:50:53 2014\" \
                capture_file=\"Mme.net_d.Ue_attach_detach\">"
  _XML_END = "</pdml>"

  _OVS_OFCTL = "ovs-ofctl"
  _GTP_PORT = 2152
  _IP_TYPE = 0x0800
  _ARP_TYPE = 0x0806
  _GTP = 4
  _DECAP_PORT = _GTP+1
  _ENCAP_PORT = _GTP+2
  _ENB_NODE_NAME="enb1"
  _ENB2_NODE_NAME="enb2"
  _OFFLOAD_NODE_NAME="server2"
  _BOB_NODE_NAME="bob"
  _ALICE_NODE_NAME="alice"
  ################

  ###Assuming known beforehand
  #enb-net-d-amac = 00:04:23:b7:42:ba, sgw_net_d_mme_mac = 00:04:23:b7:1a:04, off1_offload_mac= = 00:04:23:B7:12:66

  _off1_offload_mac = "00:04:23:B7:12:66"
  _enb_net_d_mac = "00:04:23:b7:42:ba"
  _enb2_net_d_mac = "00:04:23:b7:42:ba"
  _sgw_net_d_mme_mac = "00:04:23:b7:1a:04"
  _OFFLOAD_IP = "192.168.8.10"
  ################

  _OFFLOAD_DB = "offload.dat"
  _USER_DB = "user.dat"

  _offload_db = [] #store registered offload IPs.
  _user_db = [] #store registered IMSI of subscribed UEs.


  #P2P  
  _p2p_list = [] #list of attached UE and its bearer info
  enb1_port = -1
  enb2_port = -1
  netd_port = -1
  sgw1_teid = 0x1111
  sgw2_teid = 0x1111
  enb1_teid = 0x1111
  enb2_teid = 0x1111

  #Location routing
  locationrouting = None
  dpset = None
  switchname_to_dpid = {}
  access_switches = {}
  ipv4_allocation = {}
  imsi_server_name_map = {}
  enb_location_ip_map = {}
  server_name_to_hsw_name = {'server1':'hsw1', 'server2':'hsw2'}

  def test_rest_api(self, req, **_kwargs):
     dps = list(self.dpset.dps.keys())
     body = json.dumps(dps)
     p = req.POST
     print ("%s, %s", p['aa'], p['bb'])
     return Response(content_type='application/json', body=body)


  '''
  Get MAC addresses of offloading server, enb's net-d, sgw's net-d-mme interfaces
  '''
  def _get_MACs(self):
    print "getting MACs..."
    domain_name = subprocess.check_output(["hostname | sed s/`hostname -s`.//"], shell=True).rstrip()
    #print "Domain name = %s" % domain_name
    self._OFFLOAD_NODE = "%s.%s" % (self._OFFLOAD_NODE_NAME,domain_name)
    #print "********enb=%s..." % ENB_NODE
    ssh_p = subprocess.Popen(["ssh", self._ENB_NODE, "ifconfig | grep -B1 192.168.4.90"], stdout=subprocess.PIPE)
    self._enb_net_d_mac = re.search(r'HWaddr (.*)',ssh_p.communicate()[0]).group(1).split()[0]

    ssh_p = subprocess.Popen(["ssh", self._ENB2_NODE, "ifconfig | grep -B1 192.168.6.90"], stdout=subprocess.PIPE)
    self._enb2_net_d_mac = re.search(r'HWaddr (.*)',ssh_p.communicate()[0]).group(1).split()[0]

    ssh_p = subprocess.Popen(["ssh", self._SGW_NODE, "ifconfig | grep -B1 192.168.4.20"], stdout=subprocess.PIPE)
    self._sgw_net_d_mme_mac = re.search(r'HWaddr (.*)',ssh_p.communicate()[0]).group(1).split()[0]

    ssh_p = subprocess.Popen(["ssh", self._ALICE_NODE, "ifconfig | grep -B1 192.168.3.100 | head -1 | cut -d\" \" -f1"], stdout=subprocess.PIPE)
    self._ALICE_AN_LTE_INTERFACE = ssh_p.communicate()[0].rstrip()

    ssh_p = subprocess.Popen(["ssh", self._BOB_NODE, "ifconfig | grep -B1 192.168.3.101 | head -1 | cut -d\" \" -f1"], stdout=subprocess.PIPE)
    self._BOB_AN_LTE_INTERFACE = ssh_p.communicate()[0].rstrip()
    print "ALICE_AN_LTE_INTERFACE=%s, BOB_AN_LTE_INTERFACE=%s" % (self._ALICE_AN_LTE_INTERFACE, self._BOB_AN_LTE_INTERFACE)
    #print "enb-net-d-mac = %s, sgw_net_d_mme_mac = %s, off1_offload_mac= = %s" % (self._enb_net_d_mac, self._sgw_net_d_mme_mac, self._off1_offload_mac)
	
  '''
  Set default route for offloading node (after _get_MACs())
  '''
  def _set_default_route_servers(self):
      print "_set_default_route_servers"
      for server in self.servers:
        domain_name = subprocess.check_output(["hostname | sed s/`hostname -s`.//"], shell=True).rstrip()
        server_ulr = "%s.%s"% (server, domain_name) 
        for cellid in self.enb_location_ip_map:
            ssh_p = subprocess.Popen(["ssh", server_ulr, "sudo ip route add %s dev %s" % (self.enb_location_ip_map[cellid]['default_route'], self.servers[server]['net-server-inf'])], stdout=subprocess.PIPE)
            ssh_p.communicate()

  def _set_default_route_enb_prefix(self, ue_prefix, enb_cellid):
      enb_name = self.enb_location_ip_map[enb_cellid]['name']
      domain_name = subprocess.check_output(["hostname | sed s/`hostname -s`.//"], shell=True).rstrip()
      enb_ulr = "%s.%s"% (enb_name, domain_name) 
      enb_num = enb_name[3:4]
      #if int(enb_num) > 2:
      #    enb_num = '2'
      physical_logical_inf_map = subprocess.check_output(['ssh %s "cd /proj/PhantomNet/binh/openepc/code/script/iot-controller && ./get_interface_map.pl"' % enb_ulr], shell=True)
      an_lte_inf = re.search(r"an-lte"+enb_num+r" -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(1)
      
      #print "_set_default_route_enb %s, ue_prefix %s, an_lte interface %s" % ( enb_cellid, ue_prefix, an_lte_inf)
      ssh_p = subprocess.Popen(["ssh", enb_ulr, "sudo ip route add %s dev %s" % (ue_prefix, an_lte_inf)], stdout=subprocess.PIPE)
      ssh_p.communicate()


  def _set_default_route_enb(self, ue_ip, enb_cellid):
      #ue_prefix = "%s.0/24" % ('.'.join(ue_ip.split('.')[0:3]))
      ue_prefix = "%s/32" % ue_ip
      enb_name = self.enb_location_ip_map[enb_cellid]['name']
      domain_name = subprocess.check_output(["hostname | sed s/`hostname -s`.//"], shell=True).rstrip()
      enb_ulr = "%s.%s"% (enb_name, domain_name) 
      enb_num = enb_name[3:4]
      #if int(enb_num) > 2:
      #    enb_num = '2'
      physical_logical_inf_map = subprocess.check_output(['ssh %s "cd /proj/PhantomNet/binh/openepc/code/script/iot-controller && ./get_interface_map.pl"' % enb_ulr], shell=True)
      an_lte_inf = re.search(r"an-lte"+enb_num+r" -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(1)
      
      print "_set_default_route_enb %s, ue_prefix %s, an_lte interface %s" % ( enb_cellid, ue_prefix, an_lte_inf)
      ssh_p = subprocess.Popen(["ssh", enb_ulr, "sudo ip route add %s dev %s" % (ue_prefix, an_lte_inf)], stdout=subprocess.PIPE)
      ssh_p.communicate()

  def _set_static_arp_server(self, server_name, enb_location_ip, switch_name):
        domain_name = subprocess.check_output(["hostname | sed s/`hostname -s`.//"], shell=True).rstrip()
        server_ulr = "%s.%s"% (server_name, domain_name) 
        ssh_p = subprocess.Popen(["ssh", server_ulr, "sudo arp -s %s %s" % (enb_location_ip, self.access_switches[switch_name]['net-d-enb-mac'])], stdout=subprocess.PIPE)
        ssh_p.communicate()
  
  def _push_arp_server(self):
      for hsw in self.hsw_switches:
          dp,of, ofp = self._get_dp_from_switch_name(hsw)
          for s in self.server_name_to_hsw_name:
              if self.server_name_to_hsw_name[s] == hsw:
                server_ip = self.servers[s]['ip']
                break
          self._push_flows_ARP(dp, ofp, hsw, server_ip)
    


  def _push_flows_ARP(self, dp, ofp, hsw_name, server_ip):
    '''
    ovs-ofctl add-flow br0 in_port=$offload_inf,priority=2,eth_type=$ARP_TYPE,actions="set_field:$OFF_IP->tun_dst",output:$ENCAP
    ovs-ofctl add-flow br0 in_port=$ENCAP,priority=2,eth_type=$ARP_TYPE,actions=output:$offload_inf
    '''
    print "******Pushing APRS flows on server switch %s ....." % (hsw_name)
    
    server_port = self.hsw_switches[hsw_name]['net-server']
    actions = []
    match = ofp.OFPMatch(in_port=server_port,eth_type=self._ARP_TYPE)
    actions.append(ofp.OFPActionSetField(tun_dst=server_ip))
    actions.append(ofp.OFPActionOutput(5))
    self._add_flow(dp,2,match,actions)

    match = ofp.OFPMatch(in_port=5,eth_type=self._ARP_TYPE)
    #match = ofp.OFPMatch(in_port=4)
    actions = []
    actions.append(ofp.OFPActionOutput(server_port))
    self._add_flow(dp,2,match,actions)


  #def __init__ (self, dpset, switchname_to_dpid, access_switches, tor_switch, hsw_switches, ev):
  #def __init__ (self, dpset, switchname_to_dpid, enb_inf, enb2_inf, sgw_inf, offload_inf, gtp_inf, listen_inf, access_switches, servers, hsw_switches):
  def __init__ (self, dpset, switchname_to_dpid, enb_inf, enb2_inf, sgw_inf, offload_inf, gtp_inf, listen_inf, access_switches, servers, hsw_switches):

    #super(Sniffer, self).__init__(dpset, switchname_to_dpid, enb_inf, enb2_inf, sgw_inf, offload_inf, gtp_inf, listen_inf):
    self.record_list = []
    #self.tshark_xml = open ("tshark.xml","w")
    #Install tshark if needed.
	#self._install_pkg ("tshark")
    self.pkt_cnt = 0
    self.record_cnt = 0
    self.S1AP_init_request = []
    self.S1AP_init_response = []
    self.control_rab_info = []
    self.ho_info_dict = {}
    self.detach_requests = [] #record all detach requests
    self.detach_accepts = [] #record all detach accepts
    self.RAB_Information = []
    self.initiating_msgs = []
    self.ueip_to_enb_location_ip = {}
    self.p2p_db = {}
    self._p2p_list = {}
    self.p2p_existed = {}
    #self.rest = REST(listener_ip)
	#self.rest_history = open("rest_history","w")
    self.dpset = dpset #local datapath (switch) id
    self.switchname_to_dpid = switchname_to_dpid
    self.access_switches = access_switches
    self.servers = servers
    self.hsw_switches = hsw_switches
    self.enb_inf = enb_inf
    self.enb2_inf = enb2_inf
    self.enb1_port = enb_inf
    self.enb2_port = enb2_inf
    self.sgw_inf = sgw_inf
    self.netd_port = sgw_inf
    self.offload_inf = offload_inf
    self._GTP = gtp_inf
    self._DECAP_PORT = int(self._GTP) + 1
    self._ENCAP_PORT = int(self._GTP) + 2
    print "%d %d %d %d %d %d" % (enb_inf, sgw_inf, offload_inf, self._GTP, self._DECAP_PORT, self._ENCAP_PORT)


    '''
    #only access 1
    print "xxx %d"%switchname_to_dpid['access1']
    self.datapath = dpset.get(int(self.switchname_to_dpid['access1']))
    if self.datapath is not None:
        self.ofproto = self.datapath.ofproto
        self.parser = self.datapath.ofproto_parser
    else:
        time.sleep(2)
        self.datapath = dpset.get(int(self.switchname_to_dpid['access1']))
        self.ofproto = self.datapath.ofproto
        self.parser = self.datapath.ofproto_parser
    '''
    self._get_enb_location_ip_map('ENB.data')
    #print self.enb_location_ip_map
    self._get_imsi_server_name_map('SERVER.data')
    self.locationrouting = LocationRouting(self.dpset, self.access_switches, self.switchname_to_dpid) 
    self.access_switch_gtp = AccessSwitchGtp(self.dpset, self.switchname_to_dpid, self.access_switches)
    
    self.attached_ue_ip = open('../iot-controller-eval/e2e_delay_exp/ATTACHED_IP.data','w',0)
    self.p2p_existed_ip = open('../iot-controller-eval/e2e_delay_exp/P2P_IP.data','w',0)

    #test
    #for i in range(1,300):
    #    self._allocate_ipv4('0011040')

    #self._get_MACs()
    self._set_default_route_servers()
    self._build_database()
    self._del_flows_ryu()
    self._push_arp_server()
    self.access_switch_gtp.push_flows_bridging_ryu()
    #for enb_cellid in self.enb_location_ip_map:
    #    self._set_default_route_enb_prefix('192.190.0.0/16', enb_cellid)
    



    '''
    TEST
    '''
    #self.parse_xml_file('attach-s1ho-charlie.xml')
    #print "Done!"
    #time.sleep(10000)
    #sys.exit(1)
    '''
    ue_ip='192.235.235.68'
    ue_imsi="001011234567892"
    enb1_cellid="00011040"
    enb2_cellid="00011050"
    enb1_teid=int('0x00000013',16)
    sgw1_teid=16
    sgw2_teid=16
    enb2_teid=int('0x00001C8C',16)
    enb1_ip='192.168.4.90'
    enb2_ip='192.168.4.91'
    sgw_ip='192.168.4.20'


    self._installHoFlows(ue_ip, ue_imsi, enb1_cellid , enb2_cellid, enb1_teid, sgw1_teid, enb2_teid, sgw2_teid, sgw_ip, enb1_ip, enb2_ip)
    '''

    '''
    #test
    ue1_ip="192.53.53.157"
    ue2_ip="192.249.249.60"
    enb1_ip="192.168.4.90"
    enb2_ip="192.168.4.91"
    sgw_ip="192.168.4.20"
    enb1_teid=21
    sgw1_teid=16
    enb2_teid=22
    sgw2_teid=16
    enb1_cellid="00011040"
    enb2_cellid="00011050"
    ue1_imsi="001011234567890"
    ue2_imsi="001011234567891"

    self._installIotFlows(enb1_teid, enb1_ip, sgw1_teid, sgw_ip, ue1_ip, ue1_imsi, enb1_cellid)
    self._installIotFlows(enb2_teid, enb2_ip, sgw2_teid, sgw_ip, ue2_ip, ue2_imsi, enb2_cellid)
    #TODO: Which enb to which enb (ie, how to get enb1_cellid, enb2_cellid)
    self._installP2PFlows(ue1_ip, ue2_ip, enb1_teid, sgw1_teid, enb2_teid, sgw2_teid, sgw_ip, enb1_cellid, enb2_cellid, enb1_ip, enb2_ip)
    '''   
     
  def _get_enb_location_ip_map(self, filename):
      print "EnodeBs information:"
      for line in open(filename,'r').readlines():
        if '#' not in line and '|' in line:
            enb_info = {}
            tokens = line.split('|')
            cellid = tokens[0]
            enb_info['location_ip'] = tokens[1]
            enb_info['location_ip_netmask'] = tokens[2]
            enb_info['access_switch_name'] = tokens[3].rstrip()
            enb_info['default_route'] = tokens[4].rstrip()
            enb_info['name'] = tokens[5].rstrip()
            enb_info['start_ipv4_range'], enb_info['end_ipv4_range'] = self._get_ipv4_range(enb_info['location_ip'], enb_info['location_ip_netmask'])
            if enb_info['start_ipv4_range'] in self.enb_location_ip_map:
                print "WARNING: EnodeB %s has a repeated subnet with another eNodeB! Check your ENB.data" % cellid
            self.enb_location_ip_map[cellid] = enb_info
            self.ipv4_allocation[cellid] = []
    
  def _get_imsi_server_name_map(self, filename):
      for line in open(filename,'r').readlines():
        if '#' not in line and '|' in line:
            tokens = line.split('|')
            imsi = tokens[0]
            self.imsi_server_name_map[imsi] = tokens[1].rstrip()
   
 
  def _get_ipv4_range(self, enb_location_ip, netmask):
      start_ipv4_blocks = []
      end_ipv4_blocks = []
      ipv4_blocks = enb_location_ip.split('.')
      netmask_blocks = netmask.split('.')
      reversed_netmask_blocks = []
      for netmask in netmask_blocks:
        reversed_netmask_blocks.append(~int(netmask))
      index = 0
      for ipv4 in ipv4_blocks:
          start_ipv4_blocks.append(str(int(ipv4)&int(netmask_blocks[index])))
          end_ipv4_blocks.append(str((int(ipv4)|int(reversed_netmask_blocks[index])) & 0xFF))
          index += 1
      index = 0    
      for b in start_ipv4_blocks:
          if b == '0':
              start_ipv4_blocks[index] = '1'
          if end_ipv4_blocks[index] == '0':
              end_ipv4_blocks[index] = '1'
          index += 1

      start_ipv4 = '.'.join(start_ipv4_blocks)
      end_ipv4 = '.'.join(end_ipv4_blocks)
      return start_ipv4, end_ipv4
      


  def _get_next_ipv4(self, enb_cellid):
      enb_info = self.enb_location_ip_map[enb_cellid]   
      if len(self.ipv4_allocation[enb_cellid]) > 0:
        last_ipv4 = self.ipv4_allocation[enb_cellid][len(self.ipv4_allocation[enb_cellid])-1]
        ipv4_blocks = last_ipv4.split('.')
        index = 3
        while (index > 0):
            b = ipv4_blocks[index]
            if int(b) == 255:
                ipv4_blocks[index] = '1'
                index -= 1
            else:
                ipv4_blocks[index] = str(int(ipv4_blocks[index])+1)
                next_ipv4 = '.'.join(ipv4_blocks)
                if self._is_ipv4_in_range(next_ipv4, enb_info['start_ipv4_range'],enb_info['end_ipv4_range']) == True:
                    self.ipv4_allocation[enb_cellid].append(next_ipv4)
                    return next_ipv4
                else:
                    print "Next_ipv4 %s is out of range (%s,%s). Invalid!" % (next_ipv4, enb_info['start_ipv4_range'], enb_info['end_ipv4_range'])
                    return None
      else:
        self.ipv4_allocation[enb_cellid].append(enb_info['start_ipv4_range'])
        return enb_info['start_ipv4_range']  

  def _is_ipv4_in_range(self, ipv4, start_ipv4, end_ipv4):
      start_b = start_ipv4.split('.')
      end_b = end_ipv4.split('.')
      ipv4_b = ipv4.split('.')
      index = 0
      for b in ipv4_b:
          if int(end_b[index]) < int(b) or int(b) < int(start_b[index]):
              return False
          index += 1 
      return True

  def _allocate_ipv4(self, enb_cellid):
      next_ipv4 = self._get_next_ipv4(enb_cellid)
      print "Cellid = %s, allocated new IPv4 for UE = %s" % (enb_cellid, next_ipv4)
      return next_ipv4
        
  #def installIoTFlows(self, enb_teid, enb_ip, sgw_teid, sgw_ip, ue_ip, ue_imsi, enb_cellid):
  def installIoTFlows(self, req, **_kwargs):
    post_values = req.POST
    #enb_teid = post_values['enb_teid']
    #enb_ip = post_values['enb_ip']
    #sgw_teid = post_values['sgw_teid']
    #sgw_ip = post_values['sgw_ip']
    ue_ip = post_values['ue_ip']
    #ue_imsi = post_values['ue_imsi']
    enb_cellid = post_values['enb_cellid']

    #WHICH server?
    #   - (1) Embeded in the attach request message, or pre-provisioned using UE IMSI: flow set up BEFORE comunication.
    #   - (2) When UE sends data packet to server: flows set up WHEN communication.
    
    access_switch_name = self.enb_location_ip_map[enb_cellid]['access_switch_name']
    enb_netmask = self.enb_location_ip_map[enb_cellid]['location_ip_netmask']
    enb_location_ip = self._allocate_ipv4(enb_cellid)

    #This mapping changes uppon hand over, ie, when UE moves, ue_ip does not change, its enb_location_ip change: pkts destinated for the ue_ip are now routed to the new enb.
    if ue_ip not in self.ueip_to_enb_location_ip:
        self.ueip_to_enb_location_ip[ue_ip] = [enb_location_ip, enb_netmask, enb_cellid]
    #server_name = self.imsi_server_name_map[ue_imsi]
    server_name = "server1"
    if random.randint(0,1) == 1:
        server_name = "server2"

    hsw_name = self.server_name_to_hsw_name[server_name]

    self.attached_ue_ip.write("%s|%s|%s\n"%(ue_ip,self.servers[server_name]['ip'],enb_cellid))
    print "Installing Iot flows: ue_ip %s,\n ue_imsi = %s,\n enb_cellid = %s,\n enb_location_ip = %s,\n enb_location_ip_netmask = %s,\n on access-switch %s,\n hsw switch name = %s,\n server name = %s\n .....****" % (ue_ip, ue_imsi, enb_cellid, enb_location_ip, enb_netmask, access_switch_name, hsw_name, server_name)

    self.locationrouting.installLocationRoute(ue_ip,self.servers[server_name]['ip'], str(self.switchname_to_dpid[access_switch_name]), str(self.switchname_to_dpid[hsw_name]), enb_location_ip,enb_netmask)
    #self._set_static_arp_server(server_name, enb_location_ip, access_switch_name)
    self._set_default_route_enb(ue_ip, enb_cellid)
    return Response(status=200)
    

  def _installIotFlows(self, enb_teid, enb_ip, sgw_teid, sgw_ip, ue_ip, ue_imsi, enb_cellid):

    #WHICH server?
    #   - (1) Embeded in the attach request message, or pre-provisioned using UE IMSI: flow set up BEFORE comunication.
    #   - (2) When UE sends data packet to server: flows set up WHEN communication.
    
    access_switch_name = self.enb_location_ip_map[enb_cellid]['access_switch_name']
    enb_netmask = self.enb_location_ip_map[enb_cellid]['location_ip_netmask']
    enb_location_ip = self._allocate_ipv4(enb_cellid)

    #This mapping changes uppon hand over, ie, when UE moves, ue_ip does not change, its enb_location_ip change: pkts destinated for the ue_ip are now routed to the new enb.
    self.ueip_to_enb_location_ip[ue_ip] = [enb_location_ip, enb_netmask, enb_cellid]
    #server_name = self.imsi_server_name_map[ue_imsi]
    server_name = "server1"
    if random.randint(0,1) == 1:
        server_name = "server2"

    hsw_name = self.server_name_to_hsw_name[server_name]

    self.attached_ue_ip.write("%s|%s|%s\n"%(ue_ip,self.servers[server_name]['ip'],enb_cellid))
    print "Installing Iot flows for ue_ip %s, ue_imsi = %s, enb_cellid = %s, enb_location_ip = %s, enb_location_ip_netmask = %s, on access-switch %s, hsw switch name = %s, server name = %s .....****" % (ue_ip, ue_imsi, enb_cellid, enb_location_ip, enb_netmask, access_switch_name, hsw_name, server_name)

    #Which Server: Implementing #2
    self.access_switch_gtp.push_flows_uplink_ryu(access_switch_name, sgw_teid, ue_ip, self.servers[server_name]['ip'], self.servers[server_name]['net-server-mac'])
    self.access_switch_gtp.push_flows_downlink_ryu(access_switch_name, enb_teid, enb_ip, sgw_ip, ue_ip, enb_location_ip)
    
    self.locationrouting.installLocationRoute(ue_ip,self.servers[server_name]['ip'], str(self.switchname_to_dpid[access_switch_name]), str(self.switchname_to_dpid[hsw_name]), enb_location_ip,enb_netmask)
    #self._set_static_arp_server(server_name, enb_location_ip, access_switch_name)
    self._set_default_route_enb(ue_ip, enb_cellid)

  def _installP2PFlows(self, ue1_ip, ue2_ip, enb1_teid, sgw1_teid, enb2_teid, sgw2_teid, sgw_ip, enb1_ip, enb2_ip):
    enb1_location_ip, enb1_netmask, enb1_cellid = self.ueip_to_enb_location_ip[ue1_ip]
    enb2_location_ip, enb2_netmask, enb2_cellid = self.ueip_to_enb_location_ip[ue2_ip]
    as1_name = self.enb_location_ip_map[enb1_cellid]['access_switch_name']
    as2_name = self.enb_location_ip_map[enb2_cellid]['access_switch_name']

    print "Installing P2P flows from %s (%s/%s) to %s (%s/%s) on as1 %s, as2 %s ..." % (ue1_ip, enb1_location_ip,enb1_netmask, ue2_ip, enb2_location_ip, enb2_netmask, as1_name, as2_name)
    self.access_switch_gtp.push_flows_P2P_ryu(as1_name, as2_name, sgw1_teid, enb1_teid, sgw2_teid, enb2_teid, sgw_ip, ue1_ip, ue2_ip, enb1_location_ip, enb2_location_ip, enb1_ip, enb2_ip)
    
    #UE1 to ENB2: NEEDED for output decapuslated packets to net-d interface (shortest path)
    self.locationrouting.installLocationRoute(ue1_ip,ue2_ip, str(self.switchname_to_dpid[as1_name]), str(self.switchname_to_dpid[as2_name]), enb1_location_ip,enb1_netmask, 1, enb2_location_ip)
    #UE2 to ENB1
    self.locationrouting.installLocationRoute(ue2_ip,ue1_ip, str(self.switchname_to_dpid[as2_name]), str(self.switchname_to_dpid[as1_name]), enb2_location_ip,enb2_netmask, 1, enb1_location_ip)



  def _installHoFlows(self, ue_ip, ue_imsi, enb1_cellid , enb2_cellid, enb1_teid, sgw1_teid, enb2_teid, sgw2_teid, sgw_ip, enb1_ip, enb2_ip):
    enb1_location_ip, enb1_netmask, enb1_cellid = self.ueip_to_enb_location_ip[ue_ip]
    #'''TEST'''
    #enb1_location_ip, enb1_netmask, enb1_cellid = '192.168.1.1', '255.255.0.0', '00011040'
    as1_name = self.enb_location_ip_map[enb1_cellid]['access_switch_name']
    as2_name = self.enb_location_ip_map[enb2_cellid]['access_switch_name']
    server_name = self.imsi_server_name_map[ue_imsi]
    hsw_name = self.server_name_to_hsw_name[server_name]

    enb2_location_ip = self._allocate_ipv4(enb2_cellid)
    enb2_netmask = self.enb_location_ip_map[enb2_cellid]['location_ip_netmask']
    print "Installing HO flows from new as %s, new enb location IP %s, to server %s ..." % (as2_name, enb2_location_ip, self.servers[server_name]['ip'])
 
    '''TEst
    '''
    #ue_ip='192.235.235.68'
    #enb2_teid=int('0x00001C8C',16)
    #enb2_ip='192.168.4.91'
    #sgw_ip='192.168.4.20'

    #UL AND DL Routing flow on AS2
    self.locationrouting.installLocationRoute(ue_ip,self.servers[server_name]['ip'], str(self.switchname_to_dpid[as2_name]), str(self.switchname_to_dpid[hsw_name]), enb2_location_ip,enb2_netmask)

    #UL: decap, match sgw2_teid, change dst_mac to server2's Mac.
    self.access_switch_gtp.push_flows_uplink_ryu(as2_name, sgw2_teid, ue_ip, self.servers[server_name]['ip'], self.servers[server_name]['net-server-mac'])
    #DL: encap with tenb's TEID (enb TEID is in handover request ack from tenb to mme)
    self.access_switch_gtp.push_flows_downlink_ryu(as2_name, enb2_teid, enb2_ip, sgw_ip, ue_ip, enb2_location_ip)
  
    #UL flow at HSW: translate src_ip enb2_location_ip to enb1_location_ip for seamless.
    #DL flow at HSW: translate dst_ip enb1_location_ip to enb2_location_ip for path switch (routing to enb2).
    self.locationrouting.installServerHoFlow(str(self.switchname_to_dpid[hsw_name]), self.hsw_switches[hsw_name]['net-tor2'],self.hsw_switches[hsw_name]['net-server'], enb1_location_ip, enb2_location_ip)

    #Server Arp for returning pkt to tenb
    #self._set_static_arp_server(server_name, enb2_location_ip, as2_name)

    #Add default to UE on tenb 
    self._set_default_route_enb(ue_ip, enb2_cellid)

    #TODO: triangle flow on access switch.

  def _get_dp_from_switch_name(self, switch_name):
    print "SWITCHES = %s" % self.switchname_to_dpid
    dp = self.dpset.get(int(self.switchname_to_dpid[switch_name]))
    if dp is None:
      print "DP of switch name %s is invalid!" % switch_name
      return None, None, None
    return dp, dp.ofproto, dp.ofproto_parser


  def _del_flows_ryu(self):
    for switch_name in self.switchname_to_dpid:
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


  def _build_database(self):
    if os.path.isfile(self._USER_DB):
      user_db = open(self._USER_DB)
      for line in user_db.readlines():
        if line == "":
            continue
        self._user_db.append(line.rstrip())
    else: 
      print "NO DATABASE AVAILABLE!"
    
    for l in open("P2P.data",'r').readlines():
            tokens = l.split('|')
            if tokens[0].rstrip() in self.p2p_db:
                self.p2p_db[tokens[0].rstrip()].append(tokens[1].rstrip())
            else:
                self.p2p_db[tokens[0].rstrip()] = [tokens[1].rstrip()]


  #
  #Start sniffing
  #
  def start_sniffing (self, interfaces):
    #
    #Parsing from tshark
    #
    print "Start sniffing on interface %s " %interfaces
    tshark_out = subprocess.Popen(["sudo","tshark", "-i", interfaces, "-f", "sctp", "-T", "pdml"], stdout=subprocess.PIPE)
    packet_xml = ""
    #file_xml = self._XML_HEADER
    for line in iter(tshark_out.stdout.readline, ""):
      packet_xml += line
      #file_xml += line
      if re.match(r'</packet>',line):
        packet_xml += self._XML_END
        #self.tshark_xml.write(file_xml)
        self._parse_packet(packet_xml)
        packet_xml = self._XML_HEADER
    #add footer of XML file
    #self.tshark_xml.write(self._XML_END)


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

    '''
    #eNB cell-ID
    print "YYYYYYYY"
    print init_request
    #eutran_cgi = init_request[0].findall(".//field[@name='s1ap.ProtocolIE_Field']")
    eutran_cgi = init_request[0].findall(".//field[@show='Item 3: id-EUTRAN-CGI']")
    print eutran_cgi
    for eu in eutran_cgi:
        print eu.get("value")
        print eu.findall(".//field[@name='s1ap.EUTRAN_CGI']")[0].get("showname") if eu.findall(".//field[@name='s1ap.EUTRAN_CGI']") else None
    for ir in eutran_cgi:
        print "XXXXX"
        print ir.findall(".//field[@name='s1ap.cell_ID']")
        enb_cellid = ir.findall(".//field[@name='s1ap.cell_ID']")[0].get("value") if ir.findall(".//field[@name='s1ap.cell_ID']") else  None
        print enb_cellid
    '''
    enb_cellid = "0"
    
    IMSI = init_request[0].findall(".//field[@name='nas_eps.emm.imsi']")[0].get("show") if init_request[0].findall(".//field[@name='nas_eps.emm.imsi']") else  None
    
    #print "ABC", IMSI
    #for i in init_request[0].findall(".//field[@name='nas_eps.emm.imsi']"):
    #    print i.get("show")
    #if (ue_mme_id and ue_enb_id and s_gtp_id and TAI and GUTI and LAI and pdn):
    NAS_request = NAS_RAB_setup_request(s_gtp_id, sgw_ip, TAI, GUTI, LAI, pdn, IMSI, enb_cellid)
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
          init_msg = self._get_initiating_msg(s1ap_request.ue_enb_id)
          ue_imsi = "0"
          enb_cellid = "0"
          if init_msg:
            ue_imsi = getattr(init_msg,"ue_imsi")
            enb_cellid = getattr(init_msg, "enb_cellid")
          control_rab_info = Control_RAB_Information(s1ap_request.ue_mme_id, s1ap_request.ue_enb_id, s1ap_request.nas.pdn["address"], s1ap_response.nas.e_gtp_id, s1ap_request.nas.s_gtp_id, s1ap_response.nas.enb_ip, s1ap_request.nas.sgw_ip, s1ap_request.nas.TAI, s1ap_request.nas.LAI, s1ap_request.nas.GUTI, ue_imsi,enb_cellid)
          self.control_rab_info.append(control_rab_info)
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
    print "parsing file ........... " , xml_file
    packet_xml = ""
    for line in open(xml_file, 'r').readlines():
      packet_xml += line
      if re.match(r'</packet>',line):
        packet_xml += self._XML_END
        self._parse_packet(packet_xml)
        packet_xml = self._XML_HEADER
    sys.exit(0)
    #
    #tree = ET.parse(xml_file)
    #root = tree.getroot()
    #print "parsing file " , xml_file
    #print root
    #Iterate through packets list.
    for packet in root.iter("packet"):
      self._parse_packet(packet) 
      continue


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

  def _process_initiating_msg(self, init_msg):
    ue_imsi = init_msg[0].findall(".//field[@name='nas_eps.emm.imsi']")
    enb_cellid = init_msg[0].findall(".//field[@name='s1ap.cell_ID']")
    ue_enb_id = init_msg[0].findall(".//field[@name='s1ap.ENB_UE_S1AP_ID']")
    if ue_imsi and enb_cellid and ue_enb_id:
        imsi = ue_imsi[0].get("show")
        cellid = enb_cellid[0].get("value")
        ueenbid = ue_enb_id[0].get("show")
        print "Init msg ... " , ue_imsi[0].get("show"), enb_cellid[0].get("value"), ue_enb_id[0].get("show")
        return InitiatingMsg(ueenbid, imsi, cellid)

  def _get_initiating_msg(self,ue_enb_id):
      for init_msg in self.initiating_msgs:
          if init_msg and ue_enb_id == getattr(init_msg, "ue_enb_id"):
              return init_msg
      return None

  def _get_control_rab_info(self, ue_mme_id):
      for msg in self.control_rab_info:
          if msg and ue_mme_id == getattr(msg, "ue_mme_id"):
              return msg
      return None



  def _get_S1AP_init_request_msg(self,ue_mme_id, ue_enb_id):
      for msg in self.S1AP_init_request:
          if msg and ue_mme_id == getattr(msg, "ue_mme_id") and ue_enb_id == getattr(msg, "ue_enb_id"):
              return msg
      return None

  def _get_S1AP_init_response_msg(self,ue_mme_id, ue_enb_id):
      for msg in self.S1AP_init_response:
          if msg and ue_mme_id == getattr(msg, "ue_mme_id") and ue_enb_id == getattr(msg, "ue_enb_id"):
              return msg
      return None



  def _process_ho_msg(self, msg, msg_name):
      ue_mme_id = msg.findall(".//field[@name='s1ap.MME_UE_S1AP_ID']")[0].get('show')
      #ue_enb_id = msg.findall(".//field[@name='s1ap.ENB_UE_S1AP_ID']")[0].get('show')
      if ue_mme_id not in self.ho_info_dict:
          self.ho_info_dict[ue_mme_id] = {}

      if msg_name == 'ho_request_ack':
          print 'Controller received ho_request_ack'
          #self.ho_info_dict[ue_mme_id]['tenb_teid'] = tenb_cellid
          control_rab = self._get_control_rab_info(ue_mme_id)   
          if control_rab is None:
              print "Could not find ue_mme_session %s" % ue_mme_id
              return
          ue_ip = getattr(control_rab,'ue_ip')
          ue_imsi = getattr(control_rab,'imsi')
          enb1_cellid = getattr(control_rab,'enb_cellid')
          enb2_cellid = self.ho_info_dict[ue_mme_id]['tenb_cellid']
          enb1_teid = int('0x'+getattr(control_rab,'e_gtp_id'),16)
          sgw1_teid = int('0x'+getattr(control_rab,'s_gtp_id'),16)
          enb2_teid = int('0x'+msg.findall(".//field[@name='s1ap.gTP_TEID']")[0].get('value'),16)
          sgw2_teid = int('0x'+self.ho_info_dict[ue_mme_id]['tsgw_teid'],16)
          sgw_ip = getattr(control_rab,'sgw_ip')
          enb1_ip = getattr(control_rab,'enb_ip')
          enb2_ip = msg.findall(".//field[@name='s1ap.transportLayerAddressIPv4']")[0].get('show')

          print "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (ue_ip, ue_imsi, enb1_cellid, enb2_cellid, enb1_teid, sgw1_teid, enb2_teid, sgw2_teid, sgw_ip, enb1_ip, enb2_ip)
          self._installHoFlows(ue_ip, ue_imsi, enb1_cellid , enb2_cellid, enb1_teid, sgw1_teid, enb2_teid, sgw2_teid, sgw_ip, enb1_ip, enb2_ip)
          #TODO: install UL flow
          #Triangle flow for inflight pkts.
          #New path to the TeNB.
      if msg_name == 'ho_request':
          tsgw_teid = msg.findall(".//field[@name='s1ap.gTP_TEID']")[0].get('value')
          self.ho_info_dict[ue_mme_id]['tsgw_teid'] = tsgw_teid
      if msg_name == 'ho_required':
          tenb_cellid = msg.findall(".//field[@name='s1ap.macroENB_ID']")[0].get('value')
          self.ho_info_dict[ue_mme_id]['tenb_cellid'] = '00%s'%tenb_cellid
      if msg_name == 'ho_notify':
          print 'Controller received ho_notify'
          #TODO: delete old flow at the seNB.

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
      init_msg = packet.findall(".//field[@name='s1ap.InitialUEMessage']")
      
      ho_msg, msg_name = None, None
      ho_required_msg = packet.findall(".//field[@name='s1ap.HandoverRequired']")
      if ho_required_msg:
        ho_msg, msg_name = ho_required_msg[0], 'ho_required'
      ho_request_msg = packet.findall(".//field[@name='s1ap.HandoverRequest']")
      if ho_request_msg:
        ho_msg, msg_name = ho_request_msg[0], 'ho_request'
      ho_request_ack_msg = packet.findall(".//field[@name='s1ap.HandoverRequestAcknowledge']")
      if ho_request_ack_msg:
        ho_msg, msg_name = ho_request_ack_msg[0], 'ho_request_ack'
      #ho_command_msg = packet.findall(".//field[@name='s1ap.HandoverCommand']")
      #ho_msg, msg_name = [ho_command_msg[0], 'ho_command'] if ho_command_msg is not None
      ho_notify_msg = packet.findall(".//field[@name='s1ap.HandoverNotify']")
      if ho_notify_msg:
        ho_msg, msg_name = ho_notify_msg[0],'ho_notify'

      
      #print ho_msg, msg_name
      if ho_msg and msg_name:
        self._process_ho_msg(ho_msg, msg_name)
      

      if init_msg:
          #print "Found init_msg"
          self.initiating_msgs.append(self._process_initiating_msg(init_msg))
      
      ###
      end_1 = time.time()
	  #print "DELTA_1=%f"%(end_1-start_1)
      #
      #s1ap.InitialContextSetupRequest message
      #
      if (init_request):
        #print "Found init_request"
        self.S1AP_init_request.append(self._process_rab_init_request (init_request, self.pkt_cnt))

      #
      #s1ap.InitialContextSetupResponse message
      #
      if (init_response):
        #print "Found init_response"
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
          RAB_record = self.RAB_Information   
          enb_ip = getattr(RAB_record,"enb_ip")
          enb_gtpid = int ("0x"+getattr(RAB_record,"e_gtp_id"),16)
          sgw_gtpid = int ("0x"+getattr(RAB_record,"s_gtp_id"),16)
          sgw_ip = getattr(RAB_record,"sgw_ip")
          GUTI = getattr(RAB_record,"GUTI")
          M_TIMSI = GUTI["M_TMSI"]
          ue_ip = getattr(RAB_record,"ue_ip")
          enb_cellid = getattr(RAB_record,"enb_cellid")
          ue_imsi = getattr(RAB_record,"imsi")
          #ue_enb_id = getattr(RAB_record, "ue_enb_id")
          #init_msg = self._get_initiating_msg(ue_enb_id)
          #ue_imsi = "0"
          #enb_cellid = "0"
          #if init_msg:
          #  ue_imsi = getattr(init_msg,"ue_imsi")
          #  enb_cellid = getattr(init_msg, "enb_cellid")
          
          p2p = p2p_info(ue_ip, enb_ip, sgw_ip, enb_gtpid, sgw_gtpid, ue_imsi, enb_cellid)
          self._p2p_list[ue_imsi] = p2p
          #check if user is in database
          found = 0
		  #print M_TIMSI
          #for mtimsi in self._user_db:
          #  if M_TIMSI == mtimsi:
          #    found = 1
          #    break
          for imsi in self._user_db:
            if ue_imsi == imsi:
              found = 1
              break

          if found == 1:
            print "Attached UE is a subscriber. Do offloading..."
            self._installIotFlows(enb_gtpid, enb_ip, sgw_gtpid, sgw_ip, ue_ip, ue_imsi, enb_cellid)
            #self._push_flows_downlink_ryu(enb_gtpid, enb_ip, sgw_ip)
            #self._push_flows_uplink_ryu(sgw_gtpid, ue_ip, self._OFFLOAD_IP)

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

          p2p_1_l = []
          p2p_2_l = []
          #Attached imsi is the starting point
          #for i in self.p2p_db:
          #    print "%s->%s\n----------\n" % (i, self.p2p_db[i])
          #for i in self._p2p_list:
          #    print "%s->%s"%(i,self._p2p_list[i])
          
          #for i in self.p2p_db:
          #    print "%s:%s" % (i, self.p2p_db[i])

          if ue_imsi in self.p2p_db:
              #print "Starting ", ue_imsi
              for i in self.p2p_db[ue_imsi]:
                  #print "Starting ", self.p2p_db[ue_imsi]
                  if i in self._p2p_list:
                    p2p_1_l.append(p2p)
                    p2p_2_l.append(self._p2p_list[i])
          for i in self.p2p_db:
              #print "Ending %s: search %s" %(ue_imsi,i)
              if i in self._p2p_list and ue_imsi in self.p2p_db[i]:
                    p2p_1_l.append(self._p2p_list[i])
                    p2p_2_l.append(p2p)

          for i in range(0, len(p2p_1_l)):
              '''Skip for now'''
              #break

              p2p_1 = p2p_1_l[i]
              p2p_2 = p2p_2_l[i]
              imsi_1 = getattr(p2p_1,"ue_imsi")
              imsi_2 = getattr(p2p_2,"ue_imsi")
              enb1_cellid = getattr(p2p_1,"enb_cellid")
              enb2_cellid = getattr(p2p_2,"enb_cellid")
              #print enb1_cellid
              #print enb2_cellid
              #print self.p2p_existed
              if imsi_1 == imsi_2 or enb1_cellid == enb2_cellid or "%s-%s"%(imsi_1,imsi_2) in self.p2p_existed: #not in the same enodeb then set up path 
                print "Not install P2P for %s,%s" % (imsi_1,imsi_2)
                #p2p_1_l.remove(p2p_1)
                #p2p_2_l.remove(p2p_2)
                continue
            
              print "Install P2P path for %s(enb-%s) and %s(enb-%s)" % (imsi_1, enb1_cellid, imsi_2, enb2_cellid)
              self.p2p_existed["%s-%s"%(imsi_1, imsi_2)] = 1
              ue1_ip = getattr(p2p_1,"ue_ip")
              ue2_ip = getattr(p2p_2,"ue_ip")
              self.p2p_existed_ip.write("%s|%s\n" % (ue1_ip, ue2_ip))
              sgw1_teid = getattr(p2p_1,"sgw_teid")
              sgw2_teid = getattr(p2p_2,"sgw_teid")
              enb1_teid = getattr(p2p_1,"enb_teid")
              enb2_teid = getattr(p2p_2,"enb_teid")
              enb1_ip = getattr(p2p_1,"enb_ip")
              enb2_ip = getattr(p2p_2,"enb_ip")
              sgw_ip = getattr(p2p_1,"sgw_ip")
              #if imsi_1 in self.p2p_db and imsi_2 in self.p2p_db:

              self._installP2PFlows(ue1_ip, ue2_ip, enb1_teid, sgw1_teid, enb2_teid, sgw2_teid, sgw_ip, enb1_ip, enb2_ip)
          '''
          #BINH: remember 2 attached M_TIMSIs, create the P2P flows between them if 2 of them are in the user.dat.
          for p2p_1 in self._p2p_list:
              for p2p_2 in self._p2p_list:
                  imsi_1 = getattr(p2p_1,"ue_imsi")
                  imsi_2 = getattr(p2p_2,"ue_imsi")

                  if imsi_1 == imsi_2: 
                      continue

                  print "P2P checking for %s and %s" % (imsi_1, imsi_2)
                  ue1_ip = getattr(p2p_1,"ue_ip")
                  ue2_ip = getattr(p2p_2,"ue_ip")
                  enb1_ip = getattr(p2p_1,"enb_cellid")
                  enb2_ip = getattr(p2p_2,"enb_cellid")
                  sgw1_teid = getattr(p2p_1,"sgw_teid")
                  sgw2_teid = getattr(p2p_2,"sgw_teid")
                  enb1_teid = getattr(p2p_1,"enb_teid")
                  enb2_teid = getattr(p2p_2,"enb_teid")
                  enb1_ip = getattr(p2p_1,"enb_ip")
                  enb2_ip = getattr(p2p_2,"enb_ip")
                  sgw_ip = getattr(p2p_1,"sgw_ip")
                  if imsi_1 in self.p2p_db and imsi_2 in self.p2p_db:
                      #self._push_flows_P2P_ryu(self.enb1_port, self.enb2_port, self.netd_port, self._GTP, sgw1_teid, enb1_teid, sgw2_teid, enb2_teid, sgw_ip, enb1_ip, enb2_ip, self._sgw_net_d_mme_mac, self._enb_net_d_mac, self._enb2_net_d_mac, ip_1, ip_2)
                      #print "sgw1_teid =%02x, sgw2_teid=%02x" % (sgw1_teid, sgw2_teid)
                      #self._push_flows_P2P_ovs(self.enb1_port, self.enb2_port, self.netd_port, self._GTP, sgw1_teid, enb1_teid, sgw2_teid, enb2_teid, sgw_ip, enb1_ip, enb2_ip, self._sgw_net_d_mme_mac, self._enb_net_d_mac, self._enb2_net_d_mac, ip_1, ip_2)
                    
                      print p2p_1
                      print p2p_2   
                      self._installP2PFlows(ue1_ip, ue2_ip, enb1_teid, sgw1_teid, enb2_teid, sgw2_teid, sgw_ip, enb1_ip, enb2_ip)
                      self._p2p_list.remove(p2p_1)
                      self._p2p_list.remove(p2p_2)
                      print "p2p_list size %s" % len(self._p2p_list)
        '''   
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
    #matches.append(self.parser.OFPMatch(in_port=self.enb2_inf))
    actions.append(self.parser.OFPActionOutput(self.sgw_inf))
    self._add_flow(self.datapath,2,matches,actions)

    matches = []
    actions = []
    matches.append(self.parser.OFPMatch(in_port=self.sgw_inf))
    actions.append(self.parser.OFPActionOutput(self.enb_inf))
    #actions.append(self.parser.OFPActionOutput(self.enb2_inf))
    self._add_flow(self.datapath,2,matches,actions)


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
    #uplink_flow_to_gtp = 'in_port=%s,priority=3,eth_type=%s,nw_proto=17,tp_dst=%d,actions=output:%d' %\
    #(self.enb_inf, self._IP_TYPE, self._GTP_PORT, self._GTP)

    #uplink_flow_gtp = 'in_port=%d,priority=3,tun_id=%s,tun_src=%s,tun_dst=%s,actions=mod_dl_dst:%s,output:%d'%\
    #(self._GTP, sgw_teid, ue_ip, offload_ip, self._off1_offload_mac, self._DECAP_PORT)

    #uplink_flow_from_gtp = 'in_port=%d,priority=3,eth_type=%s,nw_src=%s,nw_dst=%s,actions=output:%s' %\
    #(self._DECAP_PORT, self._IP_TYPE, ue_ip, offload_ip, self.offload_inf)
    #uplink_normal_gtp = "in_port=%d,priority=2,actions=output:%s" % (self._GTP, self.sgw_inf)
    
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

    '''
    #3
    match = self.parser.OFPMatch(in_port=self._DECAP_PORT,eth_type=self._IP_TYPE,ipv4_src=ue_ip,ipv4_dst=offload_ip)
    actions = []
    actions.append(self.parser.OFPActionOutput(self.offload_inf))
    self._add_flow(self.datapath,3,match,actions)
    '''

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
  def _push_flows_downlink_ryu(self, enb_teid, enb_ip, sgw_ip, ue_ip, enb_location_ip):
    '''
    ovs-ofctl add-flow br0 in_port=$offload_inf,priority=2,eth_type=$IP_TYPE, nw_dst=$enb_location_ip, actions=mod_dl_dst:$ENODEB_MAC,mod_dl_src=$SGW_MAC,nw_dst=$ue_ip,"set_field:$ENODEB_TEID->tun_id","set_field:$ENODEB_IP->tun_dst","set_field:$SGW_IP->tun_src",output:$ENCAP
    ovs-ofctl add-flow br0 in_port=$ENCAP,priority=2,eth_type=$IP_TYPE,actions=output:$enb_inf   
    '''
    print "******Pushing DOWNLINK flows for eNB GTPID %s, eNB IP %s, sgw IP %s ....." % (enb_teid, enb_ip, sgw_ip)
    #downlink_flow = 'in_port=%s,priority=2,eth_type=%s,actions=mod_dl_dst:%s,mod_dl_src=%s,set_field:%s->tun_id,set_field:%s->tun_dst,set_field:%s->tun_src,output:%d' %\
    #(self.offload_inf, self._IP_TYPE, self._enb_net_d_mac, self._sgw_net_d_mme_mac, enb_teid, enb_ip, sgw_ip, self._ENCAP_PORT)

    #downlink_flow_gtp = 'in_port=%d,priority=2,eth_type=%s,actions=output:%s' %\
    #(self._ENCAP_PORT, self._IP_TYPE, self.enb_inf)

    #1
    match = []
    match.append(self.parser.OFPMatch(in_port=self.offload_inf,eth_type=self._IP_TYPE, ipv4_dst=enb_location_ip))
    actions = []
   	#actions.append(self.parser.OFPActionSetField(dl_dst=self._enb_net_d_mac,dl_src=self._sgw_net_d_mme_mac,tunnel_id=enb_teid,tun_dst=enb_ip,tun_src=sgw_ip)
    #actions.append(self.parser.OFPActionSetField(tunnel_id=enb_teid,tun_dst=enb_ip,tun_src=sgw_ip))
    actions.append(self.parser.OFPActionSetField(eth_dst=self._enb_net_d_mac))
    actions.append(self.parser.OFPActionSetField(eth_src=self._sgw_net_d_mme_mac))
    actions.append(self.parser.OFPActionSetField(ipv4_dst=ue_ip))
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
  sgw_teid=16
  ue_ip="192.168.3.100"
  offload_ip="192.168.8.10"
  sniffer = Sniffer(dpset, switchname_to_dpid, enb1_port, enb2_port, sgw_port, offload_port, gtp_port, listen_inf)

  sniffer._push_flows_uplink_ryu(sgw_teid, ue_ip, offload_ip)
  #sniffer.parse_from_file()
  #start listening
  #sniffer.push_flow_test()

  #
  #Benchmarking
  #
  #timeit.timeit(sniffer._parse_xml_file("S1AP.xml"))
  #print "%s %s" % (INTERFACES, OVS_IP)

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
