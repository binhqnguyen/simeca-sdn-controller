# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
#from ryu.controller import (dpset,event,handler,network,tunnels)
from ryu.controller import (dpset)
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import networkx as nx
import logging
LOG = logging.getLogger('ryu.app.MC')
LOG.setLevel(logging.DEBUG)

#
#Imports 
#
from sniffer import *
from detach import *
from control_rab import *
from s1ap import *
from nas import *
from rest import *
from dp import *
from dpset import *

import thread
import time
import re
from ryu import cfg
import subprocess
import xml.etree.ElementTree as ET

from ofctl_rest_listener import RestIoTApi

#whether to use encap/decap at ovs or pure IP.
ENABLE_OVS_GTP = 0


class SMORE_controller(app_manager.RyuApp):
    _SCRIPTS = "/usr/local/src/simeca/start_scripts"
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _LISTEN_INF = "eth2" #Todo: should be SGW's net_d interface
    ev = None
    bridge = "tcp:127.0.0.1"
    enb1_port = 3
    enb2_port = 4
    offload_port = 2
    sgw_port = 1
    gtp_port = 4
    ovs_ip = "127.0.0.1"
    ovs_port = 6633
    _logical_to_mac = {}    #logical interface to mac mapping (eg, net-d -> 00:11:22:33:44:55)
    _logical_to_portnumber = {}    #logical interface to port number mapping (eg, net-d -> 1)
    _OFFLOAD_NODE_NAME="cloud"
    access_switches = {}
    tor_switch = None
    hsw_switches = {}
    
    XML_TEMPLATE = "input-template-penb.xml"
   
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication,
    }

    datapaths = {}

    switchname_to_dpid = {}
    interface_to_portnumber = {}
    
    lan_list = [    'net-d-enb',
                    'offload',
                    'net-tor2',
                    'net-server'
                ]
    switch_names = [    'access1',
                            'access2',
                            'access3',
                     #       'access4',
                            'tor',
			    'hsw1'	
                     #       'hsw1',
                     #       'hsw2'
                       ]
    server_names = [ 'server1' ]
                #'server2']
    servers = {}

    def _get_port_interface_map_access_switch(self, access_switch_ulr):
        '''
        Get logical interface (eg, net-d) to MAC mapping
        '''
        logical_to_mac = {}
        physical_logical_inf_map = subprocess.check_output(['ssh -o StrictHostKeyChecking=no %s "cd %s && ./get_interface_map.pl"'% (access_switch_ulr, self._SCRIPTS)], shell=True)
        logical_to_mac["net-d"] = ":".join(re.findall(r'.{1,2}',re.search(r'net-d -> (.*) -> (.*) -> (.*)',physical_logical_inf_map).group(3)))
        
        access_switch_name = access_switch_ulr.split('.')[0]
        access_num = access_switch_ulr.split('.')[0][6:]
        #print "accnum=%s"%access_num
        #regex = r"net-d-enb" + access_num + r" -> (.*) -> (.*) -> (.*)"
        logical_to_mac["net-d-enb"] = ":".join(re.findall(r'.{1,2}',re.search(r"net-d-enb" + access_num + r" -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(3)))
        logical_to_mac["offload"] = ":".join(re.findall(r'.{1,2}',re.search(r'offload -> (.*) -> (.*) -> (.*)',physical_logical_inf_map).group(3)))
        #print "Logical interfaces to MAC mapping:"
        #print "net-d -> %s\nnet-d-mme -> %s\noffload -> %s\n" % (self._logical_to_mac["net-d"], self._logical_to_mac["net-d-mme"], self._logical_to_mac["offload"])
        
        '''
        Retrieve port number for the logical interfaces using MAC address. 
        This Python script has to be run as a root user
        '''
        info = {}
        port_desc = subprocess.check_output(['ssh -o StrictHostKeyChecking=no %s "cd %s && sudo ./ovs_port_desc.sh"' % (access_switch_ulr, self._SCRIPTS)], shell=True)
        info["net-d"] = int(re.search(r'(.*)\((.*)\): addr:%s'%logical_to_mac["net-d"],port_desc).group(1))
        self._LISTEN_INF = re.search(r'(.*)\((.*)\): addr:%s'%logical_to_mac["net-d"],port_desc).group(2)
        #self._info["net-d"] = re.search(r'(.*)\((.*): addr:%s'%self._logical_to_mac["net-d"],port_desc).group(1)
        info["net-d-enb"] = int(re.search(r'(.*)\((.*): addr:%s'%logical_to_mac["net-d-enb"],port_desc).group(1))
        info["offload"] = int(re.search(r'(.*)\((.*): addr:%s'%logical_to_mac["offload"],port_desc).group(1))

        if (ENABLE_OVS_GTP==1):
            info["gtp"] = int(re.search(r'(.*)\(gtp1\): addr:(.*)',port_desc).group(1))
            info["gtp_decap_port"] = int(info["gtp"])+1
            info["gtp_encap_port"] = int(info["gtp"])+2
        else:
            info["gtp"] = -1
            info["gtp_decap_port"] = info["net-d-enb"]
            info["gtp_encap_port"] = info["net-d-enb"]
        info["net-d-sniffer"] = self._LISTEN_INF
        info["net-d-enb-mac"] = logical_to_mac["net-d-enb"]

        self.access_switches[access_switch_name] = info
        #print "Access %s ..." % access_switch_name
        #print self.access_switches[access_switch_name]

    def _get_port_interface_map_tor_switch(self, tor_switch_ulr):
        logical_to_mac = {}
        physical_logical_inf_map = subprocess.check_output(['ssh -o StrictHostKeyChecking=no %s "cd %s && ./get_interface_map.pl"'% (tor_switch_ulr, self._SCRIPTS)], shell=True)
        logical_to_mac['offload'] = ":".join(re.findall(r'.{1,2}',re.search(r'offload -> (.*) -> (.*) -> (.*)',physical_logical_inf_map).group(3)))
        logical_to_mac['net-tor21'] = ":".join(re.findall(r'.{1,2}',re.search(r"net-tor21 -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(3)))
        #logical_to_mac['net-tor22'] = ":".join(re.findall(r'.{1,2}',re.search(r'net-tor22 -> (.*) -> (.*) -> (.*)',physical_logical_inf_map).group(3)))
        #print "Logical interfaces to MAC mapping:"
        #print "net-d -> %s\nnet-d-mme -> %s\noffload -> %s\n" % (self._logical_to_mac["net-d"], self._logical_to_mac["net-d-mme"], self._logical_to_mac["offload"])
        
        '''
        Retrieve port number for the logical interfaces using MAC address. 
        This Python script has to be run as a root user
        '''
        logical_to_portnumber = {}
        port_desc = subprocess.check_output(['ssh -o StrictHostKeyChecking=no %s "cd %s && sudo ./ovs_port_desc.sh"' % (tor_switch_ulr, self._SCRIPTS)], shell=True)
        logical_to_portnumber["net-tor21"] = int(re.search(r'(.*)\((.*): addr:%s'%logical_to_mac["net-tor21"],port_desc).group(1))
        #logical_to_portnumber["net-tor22"] = int(re.search(r'(.*)\((.*): addr:%s'%logical_to_mac["net-tor22"],port_desc).group(1))
        logical_to_portnumber["offload"] = int(re.search(r'(.*)\((.*): addr:%s'%logical_to_mac["offload"],port_desc).group(1))
        
        self.tor_switch = logical_to_portnumber
        #print "Tor ..."
        #print self.tor_switch

    def _get_port_interface_map_hsw_switch(self, hsw_switch_ulr):
        logical_to_mac = {}
        physical_logical_inf_map = subprocess.check_output(['ssh -o StrictHostKeyChecking=no %s "cd %s && ./get_interface_map.pl"'% (hsw_switch_ulr,self._SCRIPTS)], shell=True)
        
        hsw_switch_name = hsw_switch_ulr.split('.')[0]
	try:
        	hsw_num = str(hsw_switch_ulr.split('.')[0][3:])
	except:
		hsw_num = "1"
	logical_to_mac['net-server'] = ":".join(re.findall(r'.{1,2}',re.search(r"net-server" + hsw_num + r" -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(3)))
        logical_to_mac['net-tor2'] = ":".join(re.findall(r'.{1,2}',re.search(r"net-tor2" + hsw_num + r" -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(3)))
        
        '''
        Retrieve port number for the logical interfaces using MAC address. 
        This Python script has to be run as a root user
        '''
        logical_to_portnumber = {}
        port_desc = subprocess.check_output(['ssh -o StrictHostKeyChecking=no %s "cd %s && sudo ./ovs_port_desc.sh"' % (hsw_switch_ulr, self._SCRIPTS)], shell=True)
        logical_to_portnumber["net-tor2"] = int(re.search(r'(.*)\((.*): addr:%s'%logical_to_mac["net-tor2"],port_desc).group(1))
        logical_to_portnumber["net-server"] = int(re.search(r'(.*)\((.*): addr:%s'%logical_to_mac["net-server"],port_desc).group(1))
        
        self.hsw_switches[hsw_switch_name] = logical_to_portnumber
        #print "hsw switch %s ..." % (hsw_switch_name)
        #print self.hsw_switches[hsw_switch_name]

    def _get_server_info(self, server_ulr):
        info = {}
        physical_logical_inf_map = subprocess.check_output(['ssh -o StrictHostKeyChecking=no %s "cd %s && ./get_interface_map.pl"'% (server_ulr, self._SCRIPTS)], shell=True)
        server_name = server_ulr.split('.')[0]
	try:
        	server_num = str(server_ulr.split('.')[0][6:])
	except:
		server_num = "1"

	#print server_num
        info['net-server-mac'] = ":".join(re.findall(r'.{1,2}',re.search(r"net-server" + server_num + r" -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(3)))
	print physical_logical_inf_map
        #info['net-server-mac'] = ":".join(re.findall(r'.{1,2}',re.search(r"net-server -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(3)))
        info['net-server-inf'] = re.search(r"net-server" + server_num + r" -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(1)
        #info['net-server-inf'] = re.search(r"net-server -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(1)
        info['ip'] = re.search(r"net-server" + server_num + r" -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(2)
        #info['ip'] = re.search(r"net-server -> (.*) -> (.*) -> (.*)",physical_logical_inf_map).group(2)
        self.servers[server_name] = info
     
    def _get_interface_to_portnumber(self):
        for lan in ["net-d-enb", "offload", "net-d"]:
            for access in self.access_switches:
                self.interface_to_portnumber["%s-%s"%(access,lan)] = self.access_switches[access][lan]
        for lan in ["offload", "net-tor21"]:
                self.interface_to_portnumber["tor-%s"%(lan)] = self.tor_switch[lan]
        for lan in ["net-tor2", "net-server"]:
            for hsw in self.hsw_switches:
                self.interface_to_portnumber["%s-%s"%(hsw,lan)] = self.hsw_switches[hsw][lan]
        #print "Interface name to portnumber ..."
        #print self.interface_to_portnumber

    def _hex_to_int(self, str):
        try:
            return int(str,16)
        except:
            print "ERR: Can't convert \"%s\" from hex to int!" % str
            return None

    def _get_switchname_dpid (self):
        for s in self.switch_names:
            switch_ulr = "%s.%s"%(s, self.domain)
            dpid = subprocess.check_output(['ssh -o StrictHostKeyChecking=no %s "sudo ovs-ofctl show br0 | grep dpid | cut -d":" -f3"'%switch_ulr], shell=True)
            self.switchname_to_dpid[switch_ulr.split('.')[0]] = int(self._hex_to_int(dpid.rstrip()))

        LOG.debug("Switch names to dpid: ", self.switchname_to_dpid)

    def _write_dpid_to_xml(self, xml_file):
        #Replace HARDCODED dpid with new dpid
        print "Replace input-template.xml with %s" % xml_file
        subprocess.check_output(['sudo cp %s %s'%(self.XML_TEMPLATE,xml_file)], shell=True)
        tree = ET.parse(xml_file) #hardcoding file name for now
        xmlroot = tree.getroot()
        name_to_olddpid = {}
        name_to_newdpid = {}
        for child in xmlroot.findall('switch'):
            name = child.find('name').text
            dpid = child.find('dpid').text
            name_to_olddpid[name] = dpid
        #print "Olddpid ..."
        #print name_to_olddpid
        for name in name_to_olddpid:
            name_to_newdpid[name] = self.switchname_to_dpid[name]
        #print "Newdpid ..."
        #print name_to_newdpid

        #replace dpid
        for name in name_to_olddpid:
           subprocess.check_output(['sudo sed -i \'s/>%s</>%s</\' %s'%(name_to_olddpid[name],name_to_newdpid[name], xml_file)], shell=True)
        #replace portnumber
        for interfacename in self.interface_to_portnumber:
           subprocess.check_output(['sudo sed -i \'s/>%s</>%s</\' %s'%(interfacename, self.interface_to_portnumber[interfacename], xml_file)], shell=True)
        

            

    def __init__(self, *args, **kwargs):
        super(SMORE_controller, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.wsgi = kwargs['wsgi']
        self.topology_api_app = self
        self.G=nx.DiGraph()
        self.domain = subprocess.check_output(["hostname | sed s/`hostname -s`.//"], shell=True).rstrip()

        #self.switches = kwargs['switches']
        #print "DPSET= %s" % self.dpset
        #print "Init..."
        ##self.dpset = Dpset()
        #print self.dpset
                
        #Get switch dpid
        self._get_switchname_dpid()
        #Get logical interface to port number mapping for later use.

        self._get_port_interface_map_access_switch("access1.%s"% self.domain)
        self._get_port_interface_map_access_switch("access2.%s"%self.domain)
        self._get_port_interface_map_access_switch("access3.%s"%self.domain)
        #self._get_port_interface_map_access_switch("access4.%s"%self.domain)
        #self._get_port_interface_map_hsw_switch("hsw1.%s"%self.domain)
        #self._get_port_interface_map_hsw_switch("hsw2.%s"%self.domain)
        self._get_port_interface_map_hsw_switch("hsw1.%s"%self.domain)
        self._get_port_interface_map_tor_switch("tor.%s"%self.domain)
        #self._get_server_info("server1.%s"%self.domain)
        #self._get_server_info("server2.%s"%self.domain)
        self._get_server_info("server1.%s"%self.domain)
        self._get_interface_to_portnumber()
        #Construct an xml file describing the network.
        self._write_dpid_to_xml("input.xml")

        #sys.exit(0)
        self.enb1_port = int(self.access_switches['access1']['net-d-enb'])
        self.enb2_port =int(self.access_switches['access2']['net-d-enb'])
        self.sgw_port = int(self.access_switches['access1']['net-d'])
        self.offload_port = int(self.access_switches['access1']['offload'])
        self.gtp_port = int(self.access_switches['access1']['gtp'])

        #print "%d %d %d %d %d" % (self.enb1_port, self.enb2_port, self.sgw_port, self.offload_port, self.gtp_port)
        #self.enb1_port = int(self._logical_to_portnumber["net-d-enb1"])
        #self.enb2_port = int(self._logical_to_portnumber["net-d-enb2"])
        #self.sgw_port = int(self._logical_to_portnumber["net-d"])
        #self.offload_port = int(self._logical_to_portnumber["offload"])
        #self.gtp_port = int(self._logical_to_portnumber["gtp"])

        self._LISTEN_INF = re.search(r'net-d -> (.*) -> (.*) ->',subprocess.check_output(['cd %s && ./get_interface_map.pl' % (self._SCRIPTS)], shell=True)).group(1)

        #print "SMORE monitor listening to interface %s of ovs node ..." % self._LISTEN_INF
        

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        LOG.debug("In get_topology...")
        switch_list = get_switch(self.topology_api_app, None)
        #print "Switch list ... "
        #print [switch.hardware for switch in switch_list]
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        #print links_list
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        #print links
        self.G.add_nodes_from(switches)
        self.G.add_edges_from(links)
        #print "Discovered graphs:"
        #print self.G.nodes()
        #print self.G.edges(data=True)
        #print "Switch 17779081116 = %s" % self.dpset.get(17779081116)
        

    def __del__(self):
        thread.exit()

    def _start_sniffer(self, dpset, access_switches, tor_switch, hsw_switches, listen_inf):
        print "start sniffer in SMORE_controller\n"
        
        sniffer = Sniffer(dpset, access_switches, tor_switch, hsw_switches, listen_inf)
        sniffer.start_sniffing(listen_inf)
        #print "start thread sniffer %s"%listen_inf 

    def _start_sniffer_now(self, dpset, switchname_to_dpid, enb1_port, enb2_port, sgw_port, offload_port, gtp_port, listen_inf, access_switches, servers, hsw_switches):
        print "start sniffer in SMORE_controller\n"
        
        #sniffer = Sniffer(dpset, switchname_to_dpid, enb1_port, enb2_port, sgw_port, offload_port, gtp_port, listen_inf, access_switches, servers, hsw_switches)
        #sniffer.start_sniffing(listen_inf)


    

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #self.dpset.add(Dp(ev.msg.datapath_id, ev.msg.datapath, ev.msg.datapath.ofproto, ev.msg.datapath.ofproto_parser))
        #print "Collected switches len = %s" % self.dpset.dpset
        LOG.info("Collecting switches list: %s" % self.dpset.get_all())
        LOG.info("Waiting for %d switches..." % (len(self.switch_names)-len(self.dpset.get_all())))

        #RestIoTApi(dpset=self.dpset, wsgi=self.wsgi, switchname_to_dpid=self.switchname_to_dpid, enb_inf=self.enb1_port, enb2_inf=self.enb2_port,sgw_inf=self.sgw_port, offload_inf=self.offload_port,gtp_inf=self.gtp_port, listen_inf=self._LISTEN_INF,access_switches=self.access_switches,servers=self.servers, hsw_switches=self.hsw_switches);
        #print "DPSET = %s" % self.dpset.get_all_dpid()
        #if (len(self.dpset.get_all_dpid()) == len(self.switch_names)):
        #RestIoTApi(dpset=self.dpset, wsgi=self.wsgi, switchname_to_dpid=self.switchname_to_dpid, enb_inf=self.enb1_port, enb2_inf=self.enb2_port,sgw_inf=self.sgw_port, offload_inf=self.offload_port,gtp_inf=self.gtp_port, listen_inf=self._LISTEN_INF,access_switches=self.access_switches,servers=self.servers, hsw_switches=self.hsw_switches);
        if (len(self.dpset.get_all()) == len(self.switch_names)-1):
            try:
                LOG.info("START RestIoTApi LISTENER ...")
                #LOG.debug("Access switches: %s" % self.access_switches)
                RestIoTApi(dpset=self.dpset, wsgi=self.wsgi, switchname_to_dpid=self.switchname_to_dpid, enb_inf=self.enb1_port, enb2_inf=self.enb2_port,sgw_inf=self.sgw_port, offload_inf=self.offload_port,gtp_inf=self.gtp_port, listen_inf=self._LISTEN_INF,access_switches=self.access_switches,servers=self.servers, hsw_switches=self.hsw_switches);
                #print "Starting Sniffer ... on interface %s" %self._LISTEN_INF
                #thread.start_new_thread( self._start_sniffer_now, (self.dpset,self.switchname_to_dpid, self.enb1_port, self.enb2_port,self.sgw_port, self.offload_port,self.gtp_port, self._LISTEN_INF, self.access_switches, self.servers, self.hsw_switches,) )
                #thread.start_new_thread( self._start_sniffer, (self.dpset, self.switchname_to_dpid, self.access_switches, self.tor_switch, self.hsw_switches, self._LISTEN_INF) )
            except Exception, e:
		print e
                print "Error: unable to start sniffer"

        #sniffer = Sniffer(self.bridge, self.ovs_ip, self.enb_port, self.sgw_port, self.offload_port,ev)
        #sniffer.start_sniffing(self._LISTEN_INF)

    #@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    #def _packet_in_handler(self, ev):
        #print "packet in"
        #print ""


if __name__ == "__main__":
    #Testing Sniffer
    '''
    if len(sys.argv) != 6:
        print "Parameters: <net-d-enb interface> <offload-server interface> <net-d-mme interface> <ovs public IP> <ovs controller port>"
        exit(1)

    enb_port = str(sys.argv[1])
    offload_port = str(sys.argv[2])
    sgw_port = str(sys.argv[3])
    ovs_ip = str(sys.argv[4])
    ovs_port = str(sys.argv[5])
    bridge = "tcp:%s:%s" % (ovs_ip, ovs_port)

    smore = SMORE_Controller(bridge=bridge, ovs_ip=ovs_ip, enb_port=enb_inf, sgw_port=sgw_inf, offload_port=offload_inf)

    #create sniffer
    #sniffer = Sniffer(bridge, ovs_ip, enb_port, sgw_port, offload_port)
    '''
