import logging

import json
import ast
import copy
import xml.etree.ElementTree as ET
from pprint import pprint
import sys
#from webob import Response
'''
from ryu.ofproto import ether, inet, nx_match
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import (dpset,event,handler,network,tunnels)
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_common, ofproto_parser
from ryu.lib import ofctl_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib.dpid import dpid_to_str
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.topology.switches import (get_switch, 
                                    get_all_switch, 
                                    get_link,
                                    get_all_link)
'''
import networkx as nx
from ryu.ofproto import ether, inet, nx_match
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY

'''
import matplotlib.pyplot as plt
from ryu.lib import tapDB
from ryu.lib import objectTapDB as oDB
from ryu.lib import meterDB
'''

LOG = logging.getLogger('ryu.app.location_routing')
LOG.setLevel(logging.INFO)

ENABLE_OVS_GTP = 0

class LocationRouting:
    XML="/tmp/"
    switch_server_port = {}
    access_switches = {}
    switchname_to_dpid = {}
    FULL_MASK = '255.255.255.255'
    G = None
    dpset = None


    def __init__(self, dpset, access_switches,switchname_to_dpid):
	print "Create location Routing ..."
        self.dpset = dpset
        self.createNetworkGraph()
        self.access_switches = access_switches
        self.switchname_to_dpid = switchname_to_dpid

    def switch_to_server_port(self):
        for node in self.G.nodes():
            if ":" in node: #a host
                switches = self.G.edge[node]
                for s in switches:
                    self.switch_server_port[s] = self.G.edge[s][node]['port']


    def _getShortestPath(self, src_dpid, dst_dpid):
        if (nx.has_path(self.G, src_dpid, dst_dpid)) == True:
            path = nx.shortest_path(self.G, src_dpid, dst_dpid)
                    #path = nx.all_simple_paths(self.G, src_dpid_pd, dst_dpid_pd)
            index = 0
            adjusted_path = []
            for n in path:
                adjusted_path.append(n)
                if index != 0 and index < len(path)-1:
                    adjusted_path.append(n)
                index += 1

            edgesinpath=zip(adjusted_path[0:],adjusted_path[1:])
        else:
            edgesinpath = None
        return edgesinpath

    def _get_dp_from_dpid(self, dpid):
        dp = self.dpset.get(int(dpid))
        if dp is None:
            print "DP of switch name %s is invalid!" % switch_name
            return None, None, None
        return dp, dp.ofproto, dp.ofproto_parser

    #UL flow at HSW: translate src_ip enb2_location_ip to enb1_location_ip for seamless.
    #DL flow at HSW: translate dst_ip enb1_location_ip to enb2_location_ip for path switch (routing to enb2).
    def installServerHoFlow(self, server_switch_dpid, net_tor_port, net_server_port, enb1_location_ip, enb2_location_ip):
        dp, of, ofp = self._get_dp_from_dpid(int(server_switch_dpid))        
        print "installing Downlink flow for HO on server switch", server_switch_dpid
        if dp is None:
            print "Server switch, DP is NONE!"
            sys.exit(1)

        of = dp.ofproto
        ofp = dp.ofproto_parser

        #DL
        actions = []
        match = ofp.OFPMatch(in_port=net_server_port, eth_type=ether.ETH_TYPE_IP, ipv4_dst=(enb1_location_ip))
        actions.append(ofp.OFPActionSetField(ipv4_dst=enb2_location_ip))
        actions.append(ofp.OFPActionOutput(net_tor_port))
        self.mod_flow(dp, command=of.OFPFC_ADD, match=match, actions=actions, priority=4) #higher priority than the subnet match

        #UL
        actions = []
        match = ofp.OFPMatch(in_port=net_tor_port, eth_type=ether.ETH_TYPE_IP, ipv4_src=(enb2_location_ip))
        actions.append(ofp.OFPActionSetField(ipv4_src=enb1_location_ip))
        actions.append(ofp.OFPActionOutput(net_server_port))
        self.mod_flow(dp, command=of.OFPFC_ADD, match=match, actions=actions, priority=4) #higher priority than the subnet match

        return True


    #DL flow at AS1: modify dst_ip=eNB1 -> dst_ip=eNB2_location_IP -> to net_d.
    def installTriangleHoFlow(self, src_enb_switch_dpid, src_enb_switch_name, ue_ip, src_enb_location_ip, target_enb_location_ip, is_p2p_ho=0, dst_enb_location_ip=0):
        dp, of, ofp = self._get_dp_from_dpid(int(src_enb_switch_dpid))        
        if dp is None:
            print "Triangle HO flow, target enb's switch DP is NONE!"
            sys.exit(1)

        of = dp.ofproto
        ofp = dp.ofproto_parser
        net_d = self.access_switches[src_enb_switch_name]['net-d']
        #net_d_enb = self.access_switches[target_enb_switch_name]['net-d-enb']


        print "Installing Triangle flow on AS switch %s: from %s to target %s" % (src_enb_switch_dpid, src_enb_location_ip, target_enb_location_ip)
        #DL
        actions = []
        priority = 3
        if is_p2p_ho == 0:
            match = ofp.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=(src_enb_location_ip))
        else:    #if P2P match on dst_enb_location_ip too
            match = ofp.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=dst_enb_location_ip, ipv4_dst=(src_enb_location_ip))
            priority = 4
        actions.append(ofp.OFPActionSetField(ipv4_dst=target_enb_location_ip))
        actions.append(ofp.OFPActionOutput(net_d))
        
        #modify old flow
        self.mod_flow(dp,command=of.OFPFC_ADD,match=match, actions=actions,priority=priority)
        #self.mod_flow(dp, command=of.OFPFC_MODIFY_STRICT, match=match, actions=actions, priority=4) #higher priority than the subnet match


        return True

    #UL flow at AS3 in P2P HO: modify dst_ip=ue1_ip -> dst_ip=target_enb_location_IP -> to net_d, src_ip=ue2_ip -> src_ip=enb3_location_ip
    #DL flow at AS3 in P2P HO: modify src=target_enb_location_ip, dst_ip=enb3_location_ip -> src=ue1_ip, dst_ip=ue2_ip.
    def modifyEnb3P2PHoFlow(self, enb3_as_switch_dpid, enb3_as_switch_name, enb3_location_ip, enb3_mac, ue1_ip, ue2_ip, src_enb_location_ip, target_enb_location_ip):
        dp, of, ofp = self._get_dp_from_dpid(int(enb3_as_switch_dpid))        
        if dp is None:
            print "Server switch, DP is NONE!"
            sys.exit(1)

        of = dp.ofproto
        ofp = dp.ofproto_parser
        net_d_enb = self.access_switches[enb3_as_switch_name]['net-d-enb']
        offload = self.access_switches[enb3_as_switch_name]['offload']
        #net_d_enb = self.access_switches[target_enb_switch_name]['net-d-enb']


        LOG.info("Modify flows on \"enb3\" for P2P HO dst_ip=%s -> dst_ip=%s" % (src_enb_location_ip, target_enb_location_ip))

        self.installAccessUplinkFlow(dp=dp, server_destination=ue1_ip, ue_ip=ue2_ip, enb_location_ip=enb3_location_ip, gtp_decap_port=net_d_enb, outport=offload, is_destination_enb=1, target_enb_location_ip=target_enb_location_ip)
    
        self.installAccessDownlinkFlow(dp=dp, access_dpid=enb3_as_switch_dpid, ue_ip=ue2_ip, enb_location_ip=enb3_location_ip, to_gtp_encap_port=net_d_enb, is_destination_enb=1, server_ip=ue1_ip, enb_mac=enb3_mac, enb2_location_ip=target_enb_location_ip)
 
        return True




    def installIntermediaryFlow(self, dp, outport, destination, netmask, priority=3):
        LOG.debug("installing Intermediary switch flow")
        if dp is None:
            print "Intermediary switch, DP is NONE!"
            sys.exit(1)
        
        of = dp.ofproto
        ofp = dp.ofproto_parser
        match = ofp.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=(destination, netmask))

        action = [ofp.OFPActionOutput(outport)]
        #LOG.info("match %s", match)
        #LOG.info("action %s", action)
        self.mod_flow(dp, command=of.OFPFC_ADD, match=match, actions=action, priority=priority)
        return True

    #def installServerswitchDownlinkFlow(self, dp, outport, enb_destination):
    #    LOG.info("installing server switch downlink flow")
    #    return self.installIntermediaryFlow(dp, outport, enb_destination):
        

    def installAccessUplinkFlow(self, dp, server_destination, ue_ip, enb_location_ip, gtp_decap_port, outport, is_destination_enb=0, target_enb_location_ip="0", is_modify=0, server_mac="0", old_dst_enB_location_ip="0"):
            LOG.debug("installing Access switch uplink flow...")
            if dp is None:
                print "Access switch, DP is NONE!"
                sys.exit(1)


            of = dp.ofproto
            ofp = dp.ofproto_parser
            old_actions = []
            actions = []

            match = ofp.OFPMatch(in_port=gtp_decap_port, eth_type=ether.ETH_TYPE_IP,ipv4_dst=server_destination, ipv4_src=ue_ip)
            #match = ofp.OFPMatch(in_port=gtp_decap_port, ipv4_dst=server_destination, ipv4_src=ue_ip)
            #!!! Extra for P2P
            if is_destination_enb == 1:
                if target_enb_location_ip != "0": #need to translate pkt's destination ip to target enb's enb_location_ip
                    actions.append(ofp.OFPActionSetField(ipv4_dst=target_enb_location_ip))
                    #old_actions.append(ofp.OFPActionSetField(ipv4_dst=old_dst_enb_location_ip))
                else:
                    print "WARNING: Can't translate destination ue's IP to destination enb's location IP!"

            actions.append(ofp.OFPActionSetField(ipv4_src=enb_location_ip))
            old_actions.append(ofp.OFPActionSetField(ipv4_src=enb_location_ip))

            #LOG.debug("server_mac=%s", server_mac)
            #LOG.info("Match: in_port=%s, eth_type=%s, ipv4_dst=%s, ipv4_src=%s" % (gtp_decap_port, ether.ETH_TYPE_IP))
            LOG.debug("Match: %s", match)
            LOG.debug("march_dst = %s, change to = %s\n"%( server_destination,target_enb_location_ip))
            if server_mac != "0":
                actions.append(ofp.OFPActionSetField(eth_dst=server_mac))
                #should be old server_mac
                old_actions.append(ofp.OFPActionSetField(eth_dst=server_mac))
            actions.append(ofp.OFPActionOutput(outport)) #working
            old_actions.append(ofp.OFPActionOutput(outport)) #working
            
            #print "actions: %s", str(actions)
            #print "match: %s", str(match)
            
            priority = 3
            if is_destination_enb == 1:
                priority = 4
            
            #This will modify the existing flow if "match" field matches
            self.mod_flow(dp,command=of.OFPFC_ADD,match=match, actions=actions,priority=priority)
            return True
    

     
    #covered by downlink flows in access switch
    def installAccessDownlinkFlow(self, dp, access_dpid, ue_ip, enb_location_ip, to_gtp_encap_port, is_destination_enb=0, server_ip="0", enb_mac="0", enb2_location_ip="0"):
            LOG.debug("installing Access switch downlink flow...")
            if dp is None:
                print "Access switch, DP is NONE!"
                sys.exit(1)


            of = dp.ofproto
            ofp = dp.ofproto_parser
            actions = []
            
            priority = 3
            match = ofp.OFPMatch(eth_type=ether.ETH_TYPE_IP,ipv4_dst=enb_location_ip)
            #Extra for P2P
            #For DL pkts: src's IP is set to src UE's IP.
            if is_destination_enb == 1:
                if server_ip != "0" and enb2_location_ip != "0": #need to translate pkt's destination ip to target enb's enb_location_ip
                    actions.append(ofp.OFPActionSetField(ipv4_src=server_ip))
                    match = ofp.OFPMatch(eth_type=ether.ETH_TYPE_IP,ipv4_dst=enb_location_ip, ipv4_src=enb2_location_ip) #dst=enb_location_ip->dst=ue_ip and src=enb2_location_ip->src=ue2_ip(server_ip).
                    priority = 4 #!!higher priority than only matching on ipv4_dst for C2S flow.
                else:
                    print "ERROR: something wrong! P2P flow but UE2's IP is not known!"

            if enb_mac != "0":
                actions.append(ofp.OFPActionSetField(eth_dst=enb_mac))

            actions.append(ofp.OFPActionSetField(ipv4_dst=ue_ip))
            actions.append(ofp.OFPActionOutput(to_gtp_encap_port)) #working
            
            #print "actions: %s", str(actions)
            #print "match: %s", str(match)

            self.mod_flow(dp,command=of.OFPFC_ADD,match=match, actions=actions, priority=priority)
            return True

    '''
    Install prefix routing in SDN core
    Done before hand ONCE or when a new prefix is added to BS.
    '''
    def installCoreRoute(self, src_enb_ip, src_enb_netmask, dst_ip, dst_ip_netmask, src_access_dpid, dst_switch_dpid, is_destination_enb=0):
        #LOG.debug("Installing ue_ip = %s enb_location_ip %s on data path (from %s, to %s). Match dst_ip = %s", ue_ip, enb_location_ip, access_dpid, server_switch_dpid, server_ip)
        #print "Installing ue_ip = %s enb_location_ip %s on data path (from %s, to %s). Match dst_ip = %s"%(ue_ip, enb_location_ip, access_dpid, server_switch_dpid, server_ip)

        if self.G.has_node(src_access_dpid) is False:
            print "src %s dpid is not in graph!" % src_access_dpid
            return (None,None);

        if self.G.has_node(dst_switch_dpid) is False:
            print "dst %s dpid is not in graph!" % dst_switch_dpid
            return (None,None);

        LOG.debug("Compute shortest path from %s to %s" % (src_access_dpid, dst_switch_dpid))
        shortestPath = self._getShortestPath(src_access_dpid, dst_switch_dpid)


        #LOG.debug("Shortest path from %s to %s is %s" % (access_dpid, server_switch_dpid, shortestPath))
        LOG.debug("Shortest path from %s to %s is %s" % (src_access_dpid, dst_switch_dpid, shortestPath))
        index = 0 

        for src,dst in shortestPath:
            if index == 0: #access switch
                last_inport = self.G.edge[dst][src]['port']
            if index == len(shortestPath)-1: #server switches
                if is_destination_enb == 0:
                    ids_port = self.switch_server_port[dst]
                    LOG.debug("Server switch: Index %d, node %s, inport=%d, to port:%d" ,index, dst, last_inport, ids_port)
                    dp, of, ofp = self._get_dp_from_dpid(int(dst))        
                    #Uplink
                    LOG.debug("Server switch UPLINK: Index %d, node %s, to port:%d" %(index, dst, ids_port))
                    self.installIntermediaryFlow(dp, ids_port, dst_ip, dst_ip_netmask)  
                    #Downlink
                    LOG.debug("Server switch DOWNLINK: Index %d, node %s, to port:%d" %(index, dst, last_inport))
                    self.installIntermediaryFlow(dp, last_inport, src_enb_ip, src_enb_netmask)
                else:
                    LOG.debug("Server switch but P2P, NO flows are installed: Index %d, node %s" %(index, dst))

            if index < len(shortestPath)-1 and src == dst: #intermediary switches
                next_src, next_dst = shortestPath[index+1]
                ids_port = self.G.edge[next_src][next_dst]['port']
                LOG.debug("Intermediary switch: Index %s, node %s, inport=%d, outport:%d" , index, src, last_inport, ids_port)
                dp, of, ofp = self._get_dp_from_dpid(int(src))        

                priority = 3
                if dst_ip_netmask=="255.255.255.255":
                    priority=4  #higher priority for server match to distinguish from prefix match, UPLINK ONLY
                #Uplink
                LOG.debug("Intermediary switch UPLINK: Index %s, node %s,  outport:%d" % (index, src, ids_port))
                self.installIntermediaryFlow(dp, ids_port, dst_ip, dst_ip_netmask, priority=priority)
                #Downlink
                LOG.debug("Intermediary switch DOWNLINK: Index %s, node %s,  outport:%d" % (index, src, last_inport))
                self.installIntermediaryFlow(dp, last_inport, src_enb_ip, src_enb_netmask)
                last_inport = self.G.edge[next_dst][next_src]['port']
    
            index = index + 1






    '''
    Implement a path using VLAN ID based on destination's IP and source's data path id.
    '''
    def installPathIp (self, src_dpid, dst_ip):
        destination = ip_to_vlanid(dst_ip)
        installLocationRoute(self.G, dst_ip, src_dpid, dst_dpid, destination)

    '''
    - server_ip could be target enb_location_ip in P2P
    - If the destination is a ENB (is_destination_enb=1) then no server switch's rules is installed. 
        Instead, when "uplink" pkts from src eNB arrive at dst eNB, the normal "downlink" flows - which are installed when UE first attached - will 
        handle the translation from dst_ip to ue's IP.
    '''
    #def installLocationRoute(self, ue_ip, server_ip, access_dpid, server_switch_dpid, enb_location_ip, netmask, is_destination_enb = 0, target_enb_location_ip = "", server_mac="0", enb_mac="0"):
    def installLocationRoute(self, ue_ip, dst_ip, src_access_dpid, dst_switch_dpid, src_enb_location_ip, src_enb_netmask, is_destination_enb = 0, dst_enb_location_ip = "", server_mac="0", src_enb_mac="0"):
        #LOG.debug("Installing ue_ip = %s enb_location_ip %s on data path (from %s, to %s). Match dst_ip = %s", ue_ip, enb_location_ip, access_dpid, server_switch_dpid, server_ip)
        #print "Installing ue_ip = %s enb_location_ip %s on data path (from %s, to %s). Match dst_ip = %s"%(ue_ip, enb_location_ip, access_dpid, server_switch_dpid, server_ip)

        if self.G.has_node(src_access_dpid) is False:
            print "src %s dpid is not in graph!" % src_access_dpid
            return (None,None);

        if self.G.has_node(dst_switch_dpid) is False:
            print "dst %s dpid is not in graph!" % dst_switch_dpid
            return (None,None);

        LOG.debug("Compute shortest path from %s to %s" % (src_access_dpid, dst_switch_dpid))
        shortestPath = self._getShortestPath(src_access_dpid, dst_switch_dpid)


        #LOG.debug("Shortest path from %s to %s is %s" % (access_dpid, server_switch_dpid, shortestPath))
        LOG.debug("Shortest path from %s to %s is %s" % (src_access_dpid, dst_switch_dpid, shortestPath))

        index = 0 

        for src,dst in shortestPath:
            if index == 0: #access switch
                ids_port = self.G.edge[src][dst]['port']
                #LOG.debug("Access switch: Index %d, node %s, to port:%d" ,
                #        index, src, ids_port)
                dp, of, ofp = self._get_dp_from_dpid(int(src))        
                access_switch_name = ''
                for switch_name in self.switchname_to_dpid:
                    if str(self.switchname_to_dpid[switch_name]) == src:
                        access_switch_name = switch_name
                        break
                gtp_encap_port = self.access_switches[access_switch_name]['gtp_encap_port']
                gtp_decap_port = self.access_switches[access_switch_name]['gtp_decap_port']
                LOG.debug("Access switch UPLINK: Index %d, node %s, from gtp_port %d, to port:%d" % \
                (index, src, gtp_decap_port, ids_port))
                #uplink flows at access switch
                self.installAccessUplinkFlow(dp, dst_ip, ue_ip, src_enb_location_ip, gtp_decap_port, ids_port, is_destination_enb, dst_enb_location_ip, server_mac=server_mac)
                #downlink flows at access switch
                LOG.debug("Access switch DOWNLINK: Index %d, node %s, to port:%d" % \
                        (index, src, gtp_encap_port))
                if (ENABLE_OVS_GTP==0):
                    self.installAccessDownlinkFlow(dp, src, ue_ip, src_enb_location_ip, gtp_encap_port, is_destination_enb, dst_ip, enb_mac=src_enb_mac, enb2_location_ip=dst_enb_location_ip)
                last_inport = self.G.edge[dst][src]['port']

            #TODO: this is installed beforehand.
            break
            if index == len(shortestPath)-1: #server switches
                if is_destination_enb == 0:
                    ids_port = self.switch_server_port[dst]
                    LOG.debug("Server switch: Index %d, node %s, inport=%d, to port:%d" ,index, dst, last_inport, ids_port)
                    dp, of, ofp = self._get_dp_from_dpid(int(dst))        
                    #Uplink
                    LOG.debug("Server switch UPLINK: Index %d, node %s, to port:%d" %(index, dst, ids_port))
                    self.installIntermediaryFlow(dp, ids_port, dst_ip, self.FULL_MASK)
                    #Downlink
                    LOG.debug("Server switch DOWNLINK: Index %d, node %s, to port:%d" %(index, dst, last_inport))
                    self.installIntermediaryFlow(dp, last_inport, src_enb_location_ip, src_enb_netmask)
                else:
                    LOG.debug("Server switch but P2P, NO flows are installed: Index %d, node %s" %(index, dst))

            if index < len(shortestPath)-1 and src == dst: #intermediary switches
                next_src, next_dst = shortestPath[index+1]
                ids_port = self.G.edge[next_src][next_dst]['port']
                LOG.debug("Intermediary switch: Index %s, node %s, inport=%d, outport:%d" , index, src, last_inport, ids_port)
                dp, of, ofp = self._get_dp_from_dpid(int(src))        
                #Uplink
                LOG.debug("Intermediary switch UPLINK: Index %s, node %s,  outport:%d" % (index, src, ids_port))
                self.installIntermediaryFlow(dp, ids_port, dst_ip, self.FULL_MASK)
                #Downlink
                LOG.debug("Intermediary switch DOWNLINK: Index %s, node %s,  outport:%d" % (index, src, last_inport))
                self.installIntermediaryFlow(dp, last_inport, src_enb_location_ip, src_enb_netmask)
                last_inport = self.G.edge[next_dst][next_src]['port']
    
            index = index + 1


    def ip_to_vlanid (self, ip):
        return ip_to_vlanid[ip]

    def mod_flow(self, datapath, command, match, actions, priority=3):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #priority = 3
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                               actions)]
        if command is None:
            command = dp.ofproto.OFPFC_ADD

        if isinstance(match, list):
            for m in match:	
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=m, instructions=inst, command=command)
                datapath.send_msg(mod)
                #print "sent match=%s, instruction=%s, to datapath=%s"%(match, actions, datapath)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst, command=command)
            #print "sent match=%s, instruction=%s, to datapath=%s"%(match, actions, datapath)
            datapath.send_msg(mod)

    def remove_match_flows(self, datapath, match, instructions):
      """Create OFP flow mod message to remove flows from table."""
      ofproto = datapath.ofproto
      flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, table_id=0,
                                                    command=ofproto.OFPFC_DELETE, 
                                                    out_port=ofproto.OFPP_ANY,
                                                    out_group=OFPG_ANY,
                                                    match=match, instructions=instructions)
      datapath.send_msg(flow_mod)


    def mod_flow_ex(self, dp, cookie=0, cookie_mask=0, table_id=0,
        command=None, idle_timeout=0, hard_timeout=0,
        priority=0xfe, buffer_id=0xffffffff, match=None,
        actions=None, inst_type=None, out_port=None,
        out_group=None, flags=0, inst=None):

        if command is None:
            command = dp.ofproto.OFPFC_ADD

        if inst is None:
            if inst_type is None:
                inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS #OFPIT_WRITE_METADATA #OFPIT_WRITE_ACTIONS #

            inst = []
            if actions is not None:
                inst = [dp.ofproto_parser.OFPInstructionActions(
                    inst_type, actions)]

        if match is None:
            match = dp.ofproto_parser.OFPMatch()

        if out_port is None:
            out_port = dp.ofproto.OFPP_ANY

        if out_group is None:
            out_group = dp.ofproto.OFPG_ANY

        if dp is None:
            LOG.info("DP is NONE!")
            return
        LOG.info("Mod_flow out_port = %s, match = %s, inst = %s", out_port, match, inst)
        m = dp.ofproto_parser.OFPFlowMod(dp, cookie, cookie_mask,
                table_id, command,
                idle_timeout, hard_timeout,
                priority, buffer_id,
                out_port, out_group,
                flags, match, inst)

        dp.send_msg(m)



    def createNetworkGraph(self, **kwargs):
        self.G=nx.DiGraph()
        #print "adding switches and hosts"
        tree = ET.parse('%s/input.xml'% self.XML) #hardcoding file name for now
        xmlroot = tree.getroot()

        for child in xmlroot.findall('switch'):
            switch = child.find('dpid').text
            #print switch
            self.G.add_node(switch)

        for child in xmlroot.findall('links'):
            src = child.find('src').text
            dst = child.find('dst').text
            port = child.find('port').text
            #vlan = child.find('emulabvlan').text
            self.G.add_edge(src, dst, port=int(port))

        for child in xmlroot.findall('host'):
            host_mac = child.find('mac').text
            switch = child.find('switch').text
            port = child.find('port').text
            #vlan = child.find('emulabvlan').text
            self.G.add_node(host_mac)
            self.G.add_edge(switch,host_mac,port=int(port))
            self.G.add_edge(host_mac,switch,port=1) #always host port 1 is connected to the switch

        LOG.debug("printing the graph")
        LOG.debug(self.G.nodes())
        LOG.debug(self.G.edges(data=True))
        LOG.debug("Switch to server port\n")
        LOG.debug(self.switch_to_server_port())
        LOG.debug(self.switch_server_port)
        return self.G


    def str_to_actions_lim(self, ofp, actions_list,supress_outputport=False):
        #actions_str : list datatype
        #group actions are discared.
        actions_inst = []
        for action in actions_list:
            #print 'action:' +str(action)
            action_type = (action.split(':'))[0]
            #print 'action_type :' + action_type
            if action_type == 'GOTO_TABLE':
                print "not supporting goto flows as of now"
                return None
            elif action_type == 'OUTPUT':
                #print 'OUTPUT HIT'
                if supress_outputport is False:
                    action_value=(action.split(':'))[1]
                    actions_inst.append(ofp.OFPActionOutput(action_value))
            elif action_type == 'COPY_TTL_OUT':
                #print 'COPY_TTL_OUT hit'
                actions_inst.append(ofp.OFPActionCopyTtlOut())
            elif action_type == 'COPY_TTL_IN':
                #print 'COPY_TTL_IN hit'
                actions_inst.append(ofp.OFPActionCopyTtlIn())
            elif action_type == 'SET_MPLS_TTL':
                #print 'SET_MPLS_TTL hit'
                action_value=(action.split(':'))[1]
                actions_inst.append(ofp.OFPActionSetMplsTtl(action_value))
            elif action_type == 'DEC_MPLS_TTL':
                #print 'DEC_MPLS_TTL hit'
                actions_inst.append(ofp.OFPActionDecMplsTtl())
            elif action_type == 'PUSH_VLAN':
                #print 'PUSH_VLAN hit'
                action_value=(action.split(':'))[1]
                actions_inst.append(ofp.OFPActionPushVlan(action_value))
            elif action_type == 'POP_VLAN':
                #print 'POP_VLAN hit'
                actions_inst.append(ofp.OFPActionPopVlan())
            elif action_type == 'PUSH_MPLS':
                #print 'PUSH_MPLS hit'
                action_value=(action.split(':'))[1]
                actions_inst.append(ofp.OFPActionPushMpls(action_value))
            elif action_type == 'POP_MPLS':
                #print 'POP_MPLS hit'
                actions_inst.append(ofp.OFPActionPopMpls())
            elif action_type == 'SET_QUEUE':
                #print 'SET_QUEUE hit'
                action_value=(action.split(':'))[1]
                actions_inst.append(ofp.OFPActionSetQueue(action_value))
            elif action_type == 'SET_NW_TTL':
                #print 'SET_NW_TTL hit'
                action_value=(action.split(':'))[1]
                actions_inst.append(ofp.OFPActionSetNwTtl(action_value))
            elif action_type == 'DEC_NW_TTL':
                #print 'DEC_NW_TTL hit'
                actions_inst.append(ofp.OFPActionDecNwTtl())
            elif action_type == 'SET_FIELD':
                print 'SET_FIELD hit: %% skipping this field for now'
                #actions_inst.append(ofp.OFPActionSetField(arg1,arg2)) XXX
                pass #do noghint XXX
            elif action_type == 'PUSH_PBB':
                #print 'PUSH_PBB hit'
                action_value=(action.split(':'))[1]
                actions_inst.append(ofp.OFPActionPushPbb(action_value))
            elif action_type == 'POP_PBB':
                #print 'POP_PBB hit'
                actions_inst.append(ofp.OFPActionPopPbb())
            else:
                print "we got an unknown silently skip" #XXX
                pass #don't do anything as of now XXX
        print actions_inst
        return actions_inst
if __name__ == "__main__":
    vlanrouting = VlanRouting()
    G = vlanrouting.createNetworkGraph()
    #shortestPath = vlanrouting.getShortestPath(G, '00:00:00:00:00:11', '00:00:00:00:00:22')
    '''
    shortPath = vlanrouting.getShortestPath(G, '0000000000000001', '0000000000000002')
    print "\nshortestPath=%s"%shortPath
    index = 0
    print "edges=%s"%(G.edge)
    print "nodes=%s"%(G.nodes)
    print "shortestPath len=%d" % len(shortPath)
    for src,dst in shortPath:
        print src
        print dst
        ids_port = G.edge[src][dst]['port']
        print ids_port
        in_port = G.edge[dst][src]['port']
        print "inport = %d" % in_port
        print "\n"
        index += 1
    '''
    #vlanrouting.installLocationRoute(G, '192.168.3.101', '17778137524', '17779071330', 'VLAN_XX')
