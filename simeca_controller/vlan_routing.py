import logging

import json
import ast
import copy
import xml.etree.ElementTree as ET
from pprint import pprint
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


'''
import matplotlib.pyplot as plt
from ryu.lib import tapDB
from ryu.lib import objectTapDB as oDB
from ryu.lib import meterDB
'''

LOG = logging.getLogger('ryu.app.cnac_rest')
LOG.setLevel(logging.INFO)
CMD_PATTERN = r'[a-f]|all'
global tapDb
tapDb = {}
global pendingNotifications
pendingNotifications = []


class VlanRouting:
    switch_server_port = {}
    G = None

    def __init__(self, dpset):
        self.dpset = dpset
        self.createNetworkGraph()

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

    def installVlanFlow(self, dp, outport, vlan_id):
        LOG.info("installing Vlan Flow")
        of = dp.ofproto
        ofp = dp.ofproto_parser
        match = ofp.OFPMatch(vlan_vid=vlan_id)
        action = [ofp.OFPActionOutput(outport)]
        LOG.info("match %s", match)
        LOG.info("action %s", action)
        self.mod_flow(dp, command=of.OFPFC_ADD, match=match, actions=action)
        return True


    def _get_dp_from_dpid(self, dpid):
        dp = self.dpset.get(int(dpid))
        if dp is None:
            print "DP of switch name %s is invalid!" % switch_name
            return None, None, None
        return dp, dp.ofproto, dp.ofproto_parser

    def installPopVlanFlow(self, dp, outport, vlanid):
        LOG.info("installing Pop Vlan Flow")
        of = dp.ofproto
        ofp = dp.ofproto_parser
        match = ofp.OFPMatch(vlan_vid=vlanid)
        action = [ofp.OFPActionPopVlan(),
                ofp.OFPActionOutput(outport)]
        LOG.info("match %s", match)
        LOG.info("action %s", action)
        self.mod_flow(dp, command=of.OFPFC_ADD, match=match, actions=action)
        return True


    def installIDSEntry(self, dp, match, outport,
                vlan_id, trafficType=None):
            LOG.debug("installing IDS flow...")
            print "installing IDS flow..."
            of = dp.ofproto
            ofp = dp.ofproto_parser
            actions = []
            #add metering instruction for the flow
            #meter_inst = ofp.OFPInstructionMeter(flowDbEntry.get('tapID'))

            #adding double tagging to handle emulab VLAN isolation
            #LOG.debug("ids act: %s", str(actions))
            #mpls = ofp.OFPMatchField.make(of.OXM_OF_MPLS_LABEL,tap_id)
            #ids_action.append(ofp.OFPActionPushMpls(ethertype=ether.ETH_TYPE_MPLS))
            #ids_action.append(ofp.OFPActionSetField(mpls)) #working
            '''
            f = ofp.OFPMatchField.make(of.OXM_OF_VLAN_VID, vlan_id)
            actions.append(ofp.OFPActionPushVlan(ethertype=ether.ETH_TYPE_8021Q))
            actions.append(ofp.OFPActionSetField(f)) #working
            '''
            actions.append(ofp.OFPActionOutput(outport)) #working
            
            #ids_action.append(ofp.OFPActionOutput(of.OFPP_CONTROLLER)) #working

            #inst = [ofp.OFPInstructionActions(of.OFPIT_APPLY_ACTIONS, actions)] #working
            #inst.append(meter_inst)

            #Todo: match inport
            if  trafficType == 'tcp':
                LOG.info("Monitoring only TCP")
                match.set_dl_type(ether.ETH_TYPE_IP)
                match.set_ip_proto(inet.IPPROTO_TCP)
            elif trafficType == 'udp':
                LOG.info("Monitoring only UDP")
                match.set_dl_type(ether.ETH_TYPE_IP)
                match.set_ip_proto(inet.IPPROTO_UDP)
            else:
                LOG.info("supporting tcp, udp and all for now")
                LOG.info("fine grained access as future work")

            #LOG.debug("inst: %s", str(inst))
            #LOG.debug("match: %s", str(match))
            print "actions: %s", str(actions)
            print "match: %s", str(match)

            #flowDbEntry['modf2Table']= self.IDS_TABLE
            #flowDbEntry['modf2Match']= match
            #LOG.debug("flowDbEntry[modf2Match] : %s",
            #        str(flowDbEntry['modf2Match']))
            #flowDbEntry['modf2Action']= (inst)
            #LOG.debug("flowDbEntry[modf2Action] : %s",
            #        str(flowDbEntry['modf2Action']))
            #flowDbEntry['pipelineDepth'] = 2


            #self.DBEntry['mod'].append({'table': self.IDS_TABLE, 'match': match, 'inst': inst})
            #self.mod_flow(dp,command=of.OFPFC_ADD,match=match, inst=inst)
            self.mod_flow(dp,command=of.OFPFC_ADD,match=match, actions=actions)
            return True
            #return flowDbEntry;

    '''
    Implement a path using VLAN ID based on destination's IP and source's data path id.
    '''
    def installPathIp (self, src_dpid, dst_ip):
        vlan_id = ip_to_vlanid(dst_ip)
        installPathVlan(self.G, dst_ip, src_dpid, dst_dpid, vlan_id)

    '''
    Install VLAN ID on each node on a data path. Match destination IP (dst_ip)
    Input: source switch's dpid, destination switch's dpid
    '''
    def installPathVlan(self, dst_ip, src_dpid, dst_dpid, vlan_id):
        LOG.debug("Installing vlanid %s on data path (from %s, to %s). Match dst_ip = %s", vlan_id, src_dpid, dst_dpid, dst_ip)
        print "Installing vlanid %s on data path (from %s, to %s). Match dst_ip = %s"%(vlan_id, src_dpid, dst_dpid, dst_ip)

        if self.G.has_node(src_dpid) is False:
            print "src %s dpid is not in graph!" % src_dpid
            return (None,None);

        if self.G.has_node(dst_dpid) is False:
            print "dst %s dpid is not in graph!" % dst_dpid
            return (None,None);

        shortestPath = self._getShortestPath(src_dpid, dst_dpid)

        LOG.debug("Shortest path from %s to %s is %s" % (src_dpid, dst_dpid, shortestPath))
        print "Shortest path from %s to %s is %s" % (src_dpid, dst_dpid, shortestPath)

        index = 0 

        for src,dst in shortestPath:
            if index == 0:
                ids_port = self.G.edge[src][dst]['port']
                LOG.debug("Access switch: Index %d, node %s, to port:%d" ,
                        index, src, ids_port)
                print "Access switch: Index %d, node %s, to port:%d" % \
                        (index, src, ids_port)
                dp, of, ofp = self._get_dp_from_dpid(src)        
                match = ofp.OFPMatch(eth_type=0x0800,ipv4_dst=dst_ip)
                self.installIDSEntry(dp, match, ids_port, vlan_id)
                last_inport = self.G.edge[dst][src]['port']

            if index == len(shortestPath)-1:
                ids_port = self.switch_server_port[dst]
                LOG.debug("Server switch: Index %d, node %s, inport=%d, to port:%d" ,index, dst, last_inport, ids_port)
                print "Server switch: Index %d, node %s, inport=%d, to port:%d" %(index, dst, last_inport, ids_port)
                dp, of, ofp = self._get_dp_from_dpid(dst)        
                self.installPopVlanFlow(dp, ids_port, vlan_id)

            if index < len(shortestPath)-1 and src == dst:
                next_src, next_dst = shortestPath[index+1]
                ids_port = self.G.edge[next_src][next_dst]['port']
                LOG.debug("Intermediary switch: Index %s, node %s, inport=%d, outport:%d" , index, src, last_inport, ids_port)
                print "Intermediary switch: Index %s, node %s, inport=%d, outport:%d" % (index, src, last_inport, ids_port)
                last_inport = self.G.edge[next_dst][next_src]['port']
                dp, of, ofp = self._get_dp_from_dpid(src)        
                self.installVlanFlow(dp, ids_port, vlan_id)
    
            index = index + 1


    def ip_to_vlanid (self, ip):
        return ip_to_vlanid[ip]

    def mod_flow(self, datapath, command, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        priority = 3
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                               actions)]
        
        #print "Match %s" % matches
        #print "Actions %s" % actions
        if isinstance(match, list):
            for m in match:	
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=m, instructions=inst)
                datapath.send_msg(mod)
                #print "sent match=%s, instruction=%s, to datapath=%s"%(matches, inst, datapath)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst)
            #print "sent match=%s, instruction=%s, to datapath=%s"%(matches, inst, datapath)
            datapath.send_msg(mod)

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
        print "adding switches and hosts"
        tree = ET.parse('input.xml') #hardcoding file name for now
        xmlroot = tree.getroot()

        for child in xmlroot.findall('switch'):
            switch = child.find('dpid').text
            print switch
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

        print "printing the graph"
        print self.G.nodes()
        print self.G.edges(data=True);
        print "Switch to server port\n"
        self.switch_to_server_port()
        print self.switch_server_port
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
    #vlanrouting.installPathVlan(G, '192.168.3.101', '17778137524', '17779071330', 'VLAN_XX')
